//! Host-side (no QEMU) write harness for NARF's ext4 driver.
//!
//! Runs the driver in a std process against image files made by the real
//! `mkfs.ext4 -d` from a CachyOS-shaped tree, applies a seeded random
//! workload mirrored into a model, and judges the result with Linux's
//! userspace: `e2fsck -fn` must find nothing, `debugfs rdump` must see the
//! model's tree, and a fresh NARF mount must read it back. `cargo narf
//! ext4-host-rw` is the usual entry point; see `--help`.

mod check;
mod dev;
mod fixture;
mod host;
mod model;
mod narf;
mod rng;
mod workload;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::dev::ImageDev;
use crate::model::Model;
use crate::workload::{Params, Workload};

const USAGE: &str = "\
narf-ext4-host — host-side ext4 write harness (no QEMU)

USAGE: narf-ext4-host [OPTIONS]

  --seed N          first workload seed (default 1)
  --seeds N         seeds per scenario (default 2)
  --ops N           operations per run (default 1500)
  --scenario LIST   comma-separated subset of: baseline,lifecycle,gate,uninit,
                    htree,extents,replay,crash,reuse,abort,orphan
                    (default all)
  --workdir DIR     scratch directory (default target/ext4-host)
  --keep            keep the images of passing runs
";

struct Opts {
    seed: u64,
    seeds: u64,
    ops: usize,
    scenarios: Vec<String>,
    workdir: PathBuf,
    keep: bool,
}

fn parse_args() -> Opts {
    let mut o = Opts {
        seed: 1,
        seeds: 2,
        ops: 1500,
        scenarios: Vec::new(),
        workdir: PathBuf::from("target/ext4-host"),
        keep: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| panic!("{a} needs a value"));
        match a.as_str() {
            "--seed" => o.seed = val().parse().expect("--seed N"),
            "--seeds" => o.seeds = val().parse().expect("--seeds N"),
            "--ops" => o.ops = val().parse().expect("--ops N"),
            "--scenario" => o.scenarios = val().split(',').map(str::to_string).collect(),
            "--workdir" => o.workdir = PathBuf::from(val()),
            "--keep" => o.keep = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => {
                eprint!("unknown argument {other}\n\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    o
}

/// Judge an image after NARF let go of it.
/// After an unmount a journaled filesystem is left as Linux leaves it: no
/// `needs_recovery`, no `orphan_present`, an empty log (`s_start` 0).
fn journal_left_clean(image: &Path) -> Result<(), String> {
    let features = sb_field(image, "Filesystem features");
    if !features.contains("has_journal") {
        return Ok(());
    }
    let start = sb_field(image, "Journal start");
    if features.contains("needs_recovery") || features.contains("orphan_present") || start != "0" {
        return Err(format!(
            "journal not left clean: {features}; journal start {start}"
        ));
    }
    Ok(())
}

fn verdict(image: &Path, expected: &Model, scratch: &Path) -> Result<(), String> {
    journal_left_clean(image)?;
    let (code, out) = check::e2fsck(image);
    if code != 0 {
        return Err(format!(
            "e2fsck -fn exited {code}:\n{}",
            workload::tail(&out, 40)
        ));
    }
    let linux = check::debugfs_tree(image, scratch);
    let d = expected.diff(&linux, 20);
    if !d.is_empty() {
        return Err(format!(
            "debugfs sees a different tree:\n  {}",
            d.join("\n  ")
        ));
    }
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(image, 512));
    let fs = narf::mount(dev).map_err(|e| format!("remount: {e}"))?;
    let narf = narf::walk(&fs.root())?;
    drop(fs);
    narf_block::registry::__reset_for_test();
    journal_left_clean(image)?;
    let d = expected.diff(&narf, 20);
    if !d.is_empty() {
        return Err(format!(
            "a NARF remount sees a different tree:\n  {}",
            d.join("\n  ")
        ));
    }
    Ok(())
}

/// Linear directories only: changes under `/work`, which the fixture
/// leaves empty, so no operation needs an htree split.
fn baseline(o: &Opts, seed: u64) -> Result<String, String> {
    let fx = fixture::build(
        &o.workdir,
        &format!("baseline-{seed}"),
        &fixture::Spec::root(),
        seed,
    );
    let model = Model::load_host(&fx.tree);
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
    let fs = narf::mount(dev)?;
    let mut w = Workload::new(seed, model, fs.root());
    w.run(&Params {
        ops: o.ops,
        roots: vec!["/work".into()],
        hot_dirs: Vec::new(),
        max_file: 256 * 1024,
    })?;
    host::block_on(fs.root().syncfs()).map_err(|e| format!("final syncfs: {e:?}"))?;
    // The workload's directory handles hold the volume: let go of them too,
    // so the last unmount marks the filesystem clean.
    let (model, counts) = (w.model.clone(), format!("{:?}", w.counts));
    drop(w);
    drop(fs);
    narf_block::registry::__reset_for_test();
    if sb_field(&fx.image, "Filesystem state") != "clean" {
        return Err("the last unmount did not mark the filesystem clean".into());
    }
    verdict(
        &fx.image,
        &model,
        &o.workdir.join(format!("baseline-{seed}/rdump")),
    )?;
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(format!("baseline-{seed}")));
    }
    Ok(counts)
}

fn sb_field(image: &Path, name: &str) -> String {
    check::superblock(image)
        .get(name)
        .cloned()
        .unwrap_or_default()
}

fn debugfs_w(image: &Path, cmd: &str) {
    let ok = std::process::Command::new("debugfs")
        .args(["-w", "-R", cmd])
        .arg(image)
        .output()
        .expect("run debugfs")
        .status
        .success();
    assert!(ok, "debugfs -w {cmd}");
}

/// The superblock across a root-rw mount, as Linux keeps it, and `e2fsck
/// -fn` clean after it:
/// - journaled (the default mkfs): "clean" while mounted, with
///   `needs_recovery` (and `orphan_present`, for the orphan file) set; the
///   journal sequence advances as transactions commit; after a remount
///   read-only both flags are gone and the log is empty (start 0);
/// - without a journal (`-O ^has_journal`): "not clean" while mounted, and
///   "clean" again after the remount.
///
/// Either way the mount is counted and `syncfs` never marks the filesystem
/// clean.
fn lifecycle(o: &Opts, seed: u64) -> Result<String, String> {
    use narf_filesystem::sb_flags::RDONLY;
    let mut report = Vec::new();
    for journaled in [true, false] {
        let name = format!(
            "lifecycle-{seed}-{}",
            if journaled { "jbd" } else { "nojournal" }
        );
        let spec = fixture::Spec {
            mkfs_args: if journaled {
                Vec::new()
            } else {
                vec!["-O".into(), "^has_journal".into()]
            },
            ..fixture::Spec::root()
        };
        let fx = fixture::build(&o.workdir, &name, &spec, seed);
        let model = Model::load_host(&fx.tree);
        let mounts_before: u32 = sb_field(&fx.image, "Mount count").parse().unwrap_or(0);
        let seq_before = sb_field(&fx.image, "Journal sequence");
        let uuid = narf::image_uuid(&fx.image);
        let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
        let fs = narf::mount_root_rw(dev, &uuid).map_err(|e| format!("root-rw mount: {e:?}"))?;
        let state = sb_field(&fx.image, "Filesystem state");
        let features = sb_field(&fx.image, "Filesystem features");
        let mounts: u32 = sb_field(&fx.image, "Mount count").parse().unwrap_or(0);
        let want_state = if journaled { "clean" } else { "not clean" };
        if state != want_state || mounts != mounts_before + 1 {
            return Err(format!(
                "journaled={journaled}: mounted: state {state:?}, mount count {mounts} (was {mounts_before})"
            ));
        }
        if journaled
            && (!features.contains("needs_recovery") || !features.contains("orphan_present"))
        {
            return Err(format!(
                "mounted: needs_recovery/orphan_present not set: {features}"
            ));
        }
        let mut w = Workload::new(seed, model, fs.root());
        w.run(&Params {
            ops: o.ops / 4,
            roots: vec!["/work".into()],
            hot_dirs: Vec::new(),
            max_file: 128 * 1024,
        })?;
        host::block_on(fs.root().syncfs()).map_err(|e| format!("syncfs: {e:?}"))?;
        if sb_field(&fx.image, "Filesystem state") != want_state {
            return Err("syncfs must not change the filesystem state".into());
        }
        if journaled {
            let seq = sb_field(&fx.image, "Journal sequence");
            if seq == seq_before || sb_field(&fx.image, "Journal start") == "0" {
                return Err(format!(
                    "no transaction committed: sequence {seq} (was {seq_before}), start {}",
                    sb_field(&fx.image, "Journal start")
                ));
            }
        }
        host::block_on(fs.reconfigure_sb_async(RDONLY, RDONLY, ""))
            .map_err(|e| format!("remount read-only: {e:?}"))?;
        let clean = sb_field(&fx.image, "Filesystem state");
        if clean != "clean" {
            return Err(format!("after remount read-only the state is {clean:?}"));
        }
        if journaled {
            let features = sb_field(&fx.image, "Filesystem features");
            if features.contains("needs_recovery")
                || features.contains("orphan_present")
                || sb_field(&fx.image, "Journal start") != "0"
            {
                return Err(format!(
                    "after remount read-only: {features}; journal start {}",
                    sb_field(&fx.image, "Journal start")
                ));
            }
        }
        let (model, counts) = (w.model.clone(), w.counts.values().sum::<usize>());
        drop(w);
        drop(fs);
        narf_block::registry::__reset_for_test();
        verdict(&fx.image, &model, &o.workdir.join(format!("{name}/rdump")))?;
        if !o.keep {
            let _ = std::fs::remove_dir_all(o.workdir.join(&name));
        }
        report.push(format!(
            "{}: {counts} ops",
            if journaled { "journaled" } else { "no journal" }
        ));
    }
    Ok(report.join(", "))
}

/// root-rw refuses what e2fsck has not checked, an unclean filesystem or one
/// with recorded errors, and a feature NARF cannot write (quota). Each
/// read-write request fails with EROFS and leaves the image bit-identical.
/// An orphan list is not refused: the root-rw mount finishes it
/// (`ext4_orphan_cleanup`), and e2fsck then finds the filesystem clean.
fn gate(o: &Opts, seed: u64) -> Result<String, String> {
    let name = format!("gate-{seed}");
    let spec = fixture::Spec {
        lib_files: 50,
        packages: 10,
        ..fixture::Spec::root()
    };
    let fx = fixture::build(&o.workdir, &name, &spec, seed);
    let uuid = narf::image_uuid(&fx.image);
    for (cmd, what) in [
        ("ssv state 0", "an unclean filesystem"),
        ("ssv state 3", "a filesystem with errors"),
        ("feature quota", "a feature NARF cannot write"),
    ] {
        let image = o.workdir.join(format!("{name}/case.img"));
        std::fs::copy(&fx.image, &image).unwrap();
        debugfs_w(&image, cmd);
        let before = std::fs::read(&image).unwrap();
        let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&image, 512));
        match narf::mount_root_rw(dev, &uuid) {
            Err(narf_filesystem::FsError::ReadOnly) => {}
            other => {
                return Err(format!(
                    "{what}: root-rw must refuse with EROFS, got {:?}",
                    other.map(|_| "a writable mount")
                ))
            }
        }
        narf_block::registry::__reset_for_test();
        if std::fs::read(&image).unwrap() != before {
            return Err(format!("{what}: a refused mount changed the image"));
        }
    }
    // An inode with no link on the orphan list, as a crash with it open
    // leaves it (debugfs `unlink` leaves the link count alone).
    let image = o.workdir.join(format!("{name}/orphan.img"));
    std::fs::copy(&fx.image, &image).unwrap();
    debugfs_w(&image, "write /dev/null orphan");
    let ino = *root_inos(&image, "orphan")
        .get("orphan")
        .ok_or("no inode for /orphan")?;
    debugfs_w(&image, "unlink /orphan");
    debugfs_w(&image, &format!("sif <{ino}> links_count 0"));
    debugfs_w(&image, &format!("ssv last_orphan {ino}"));
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&image, 512));
    let fs = narf::mount_root_rw(dev, &uuid)
        .map_err(|e| format!("root-rw must mount a filesystem with an orphan list: {e:?}"))?;
    drop(fs);
    narf_block::registry::__reset_for_test();
    if orphan_record(&image).1 != 0 || inode_in_use(&image, ino) {
        return Err("the root-rw mount must release the orphan and empty the list".into());
    }
    journal_left_clean(&image)?;
    let (code, out) = check::e2fsck(&image);
    if code != 0 {
        return Err(format!("e2fsck -fn after the orphan cleanup:\n{out}"));
    }
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(&name));
    }
    Ok("3 refusals, orphan list finished".into())
}

/// Lazily initialized groups (`BLOCK_UNINIT` / `INODE_UNINIT`): a 4 GiB
/// image whose small tree leaves most groups uninitialized, then enough
/// data to fill the initialized groups and enough files to use up group 0's
/// inodes. e2fsck then checks every bitmap, flag and count NARF wrote.
fn uninit(o: &Opts, seed: u64) -> Result<String, String> {
    let name = format!("uninit-{seed}");
    let spec = fixture::Spec {
        size_mib: 4096,
        lib_files: 50,
        packages: 10,
        ..fixture::Spec::root()
    };
    let fx = fixture::build(&o.workdir, &name, &spec, seed);
    let uninit_before = check::uninit_groups(&fx.image);
    if uninit_before.0 == 0 || uninit_before.1 == 0 {
        return Err(format!(
            "mkfs left no uninitialized groups: {uninit_before:?}"
        ));
    }
    let mut model = Model::load_host(&fx.tree);
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
    let fs = narf::mount(dev)?;
    let root = fs.root();
    let mut rng = rng::Rng::new(seed);
    let chunk = rng.bytes(1 << 20);
    host::block_on(async {
        let work = narf::dir_at(&root, "/work").await?;
        // Data past the initialized groups' free space.
        for i in 0..24 {
            let f = work.create(&format!("big{i}")).await?;
            for c in 0..64u64 {
                let mut off = c << 20;
                let mut rest = &chunk[..];
                while !rest.is_empty() {
                    let n = f.write(off, rest).await?;
                    off += n as u64;
                    rest = &rest[n..];
                }
            }
        }
        // Inodes past group 0's.
        let many = work.mkdir("many").await?;
        for i in 0..9000 {
            many.create(&format!("e{i}")).await?;
        }
        root.syncfs().await
    })
    .map_err(|e| format!("uninit workload: {e:?}"))?;
    for i in 0..24 {
        let mut data = Vec::with_capacity(64 << 20);
        for _ in 0..64 {
            data.extend_from_slice(&chunk);
        }
        model
            .nodes
            .insert(format!("/work/big{i}"), model::Node::File(data));
    }
    model.nodes.insert("/work/many".into(), model::Node::Dir);
    for i in 0..9000 {
        model
            .nodes
            .insert(format!("/work/many/e{i}"), model::Node::File(Vec::new()));
    }
    drop(root);
    drop(fs);
    narf_block::registry::__reset_for_test();
    let uninit_after = check::uninit_groups(&fx.image);
    if uninit_after.0 >= uninit_before.0 || uninit_after.1 >= uninit_before.1 {
        return Err(format!(
            "the workload never initialized a group: block/inode uninit {uninit_before:?} -> {uninit_after:?}"
        ));
    }
    verdict(&fx.image, &model, &o.workdir.join(format!("{name}/rdump")))?;
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(&name));
    }
    Ok(format!(
        "uninit groups (block, inode) {uninit_before:?} -> {uninit_after:?}"
    ))
}

/// Indexed directories: inserts that split full leaves, fill the root
/// index and add the second index level (1 KiB blocks, so the root holds
/// 123 leaves), then deletes, judged by e2fsck's htree checks.
fn htree(o: &Opts, seed: u64) -> Result<String, String> {
    let name = format!("htree-{seed}");
    let spec = fixture::Spec {
        block_size: 1024,
        size_mib: 512,
        lib_files: 600,
        packages: 20,
        ..fixture::Spec::root()
    };
    let fx = fixture::build(&o.workdir, &name, &spec, seed);
    let model = Model::load_host(&fx.tree);
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
    let fs = narf::mount(dev)?;
    let mut w = Workload::new(seed, model, fs.root());
    // Mostly creates into the indexed /usr/lib, with the usual mix around.
    w.run(&Params {
        ops: o.ops * 3,
        roots: vec!["/usr/lib".into(), "/work".into()],
        hot_dirs: vec!["/usr/lib".into()],
        max_file: 4096,
    })?;
    // 6000 long names: about 430 leaves at 1 KiB, past the root's 123, so
    // the index gains its second level and its nodes split.
    let root = fs.root();
    let mut names = Vec::new();
    host::block_on(async {
        let lib = narf::dir_at(&root, "/usr/lib").await?;
        for i in 0..6000 {
            let n = format!("bulk_{i:05}_{}", "x".repeat(50));
            lib.create(&n).await?;
            names.push(n);
        }
        // Then delete every third through the index.
        for n in names.iter().step_by(3) {
            lib.unlink(n).await?;
        }
        Ok::<(), narf_filesystem::FsError>(())
    })
    .map_err(|e| format!("bulk htree inserts: {e:?}"))?;
    drop(root);
    for (i, n) in names.iter().enumerate() {
        if i % 3 != 0 {
            w.model
                .nodes
                .insert(format!("/usr/lib/{n}"), model::Node::File(Vec::new()));
        }
    }
    host::block_on(fs.root().syncfs()).map_err(|e| format!("syncfs: {e:?}"))?;
    let levels = check::htree_levels(&fx.image, "/usr/lib");
    if levels != Some(1) {
        return Err(format!(
            "/usr/lib should have grown a second index level, has {levels:?}"
        ));
    }
    let (model, counts) = (w.model.clone(), format!("{:?}", w.counts));
    drop(w);
    drop(fs);
    narf_block::registry::__reset_for_test();
    verdict(&fx.image, &model, &o.workdir.join(format!("{name}/rdump")))?;
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(&name));
    }
    Ok(format!("/usr/lib indirect levels {levels:?}; {counts}"))
}

/// Extent trees past one index level: a sparse file written one block in
/// two, in shuffled order, so inserts land mid-leaf and ahead of a
/// subtree's first key, splitting leaves and index nodes and growing the
/// tree. At 1 KiB (4 entries in the root, 84 in a block) 30000 extents need
/// depth 3; at 2 KiB the tail checksum sits before the block's end
/// (`EXT4_EXTENT_TAIL_OFFSET` = 2040). Judged by e2fsck's extent checks and
/// a byte compare.
fn extents(o: &Opts, seed: u64) -> Result<String, String> {
    let mut report = Vec::new();
    for (block_size, want_depth) in [(1024u32, 3u32), (2048, 2)] {
        let name = format!("extents-{seed}-{block_size}");
        let spec = fixture::Spec {
            block_size,
            size_mib: 256,
            lib_files: 20,
            packages: 5,
            ..fixture::Spec::root()
        };
        let fx = fixture::build(&o.workdir, &name, &spec, seed);
        let mut model = Model::load_host(&fx.tree);
        let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
        let fs = narf::mount(dev)?;
        let root = fs.root();
        let bs = u64::from(block_size);
        let n = 30_000u64;
        let mut rng = rng::Rng::new(seed);
        let mut order: Vec<u64> = (0..n).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i + 1));
        }
        let mut data = vec![0u8; ((2 * n - 1) * bs) as usize];
        for &i in &order {
            let off = (2 * i * bs) as usize;
            for (k, b) in data[off..off + bs as usize].iter_mut().enumerate() {
                *b = (i as usize * 7 + k) as u8 | 1;
            }
        }
        host::block_on(async {
            let work = narf::dir_at(&root, "/work").await?;
            let f = work.create("sparse").await?;
            for &i in &order {
                let off = 2 * i * bs;
                let mut rest = &data[off as usize..(off + bs) as usize];
                let mut at = off;
                while !rest.is_empty() {
                    let k = f.write(at, rest).await?;
                    at += k as u64;
                    rest = &rest[k..];
                }
            }
            root.syncfs().await
        })
        .map_err(|e| format!("{block_size}-byte blocks: sparse writes: {e:?}"))?;
        model
            .nodes
            .insert("/work/sparse".into(), model::Node::File(data));
        drop(root);
        drop(fs);
        narf_block::registry::__reset_for_test();
        let depth = check::extent_depth(&fx.image, "/work/sparse");
        if depth.is_none_or(|d| d < want_depth) {
            return Err(format!(
                "{block_size}-byte blocks: the tree should reach depth {want_depth}, has {depth:?}"
            ));
        }
        verdict(&fx.image, &model, &o.workdir.join(format!("{name}/rdump")))
            .map_err(|e| format!("{block_size}-byte blocks: {e}"))?;
        if !o.keep {
            let _ = std::fs::remove_dir_all(o.workdir.join(&name));
        }
        report.push(format!("{block_size}: depth {}", depth.unwrap_or(0)));
    }
    Ok(report.join(", "))
}

/// One filesystem block of `image`.
fn fs_block(image: &Path, bs: u64, block: u64) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(image).unwrap();
    f.seek(SeekFrom::Start(block * bs)).unwrap();
    let mut out = vec![0u8; bs as usize];
    f.read_exact(&mut out).unwrap();
    out
}

/// A journal written by e2fsprogs (`debugfs` `jo -c`, `jw`, `jc`), replayed
/// by a NARF mount and, on a copy, by `e2fsck -fy`:
/// - T1 logs blocks A and B; T2 revokes A; T3 logs C, which begins with the
///   JBD2 magic (escaped in the log); T4 logs D without a commit.
/// - Both replays must leave A, B, C and D the same: A as before (revoked
///   later), B and C replayed, D as before (uncommitted).
/// - After the NARF mount the log is empty, needs_recovery is gone and
///   `e2fsck -fn` finds nothing.
///
/// Run as a read-write mount and as a read-only one: Linux replays on both
/// when the device can be written.
fn replay(o: &Opts, seed: u64) -> Result<String, String> {
    let name = format!("replay-{seed}");
    let spec = fixture::Spec {
        lib_files: 50,
        packages: 10,
        ..fixture::Spec::root()
    };
    let fx = fixture::build(&o.workdir, &name, &spec, seed);
    let dir = o.workdir.join(&name);
    let bs: u64 = sb_field(&fx.image, "Block size").parse().unwrap();
    let count: u64 = sb_field(&fx.image, "Block count").parse().unwrap();
    // Four free blocks past the middle: their old contents are known and
    // nothing references them.
    let ffb = std::process::Command::new("debugfs")
        .args(["-R", &format!("ffb 4 {}", count / 2)])
        .arg(&fx.image)
        .output()
        .expect("run debugfs ffb");
    let found: Vec<u64> = String::from_utf8_lossy(&ffb.stdout)
        .split_whitespace()
        .filter_map(|w| w.parse().ok())
        .collect();
    let [a, b, c, d] = found[..] else {
        return Err(format!("ffb found {found:?}"));
    };
    let mut rng = rng::Rng::new(seed);
    let mut bytes = |n: u64| -> Vec<u8> { (0..n).map(|_| rng.next() as u8).collect() };
    let f1 = bytes(2 * bs);
    let mut f2 = bytes(bs);
    f2[..4].copy_from_slice(&0xC03B_3998u32.to_be_bytes());
    let f3 = bytes(bs);
    for (file, data) in [("f1", &f1), ("f2", &f2), ("f3", &f3)] {
        std::fs::write(dir.join(file), data).unwrap();
    }
    std::fs::write(dir.join("empty"), b"").unwrap();
    let cmds = format!(
        "jo -c\njw -b {a},{b} {f1}\njw -r {a} {empty}\njw -b {c} {f2}\njw -b {d} -c {f3}\njc\n",
        f1 = dir.join("f1").display(),
        f2 = dir.join("f2").display(),
        f3 = dir.join("f3").display(),
        empty = dir.join("empty").display(),
    );
    std::fs::write(dir.join("cmds"), cmds).unwrap();
    let dirty = dir.join("dirty.img");
    std::fs::copy(&fx.image, &dirty).unwrap();
    let ok = std::process::Command::new("debugfs")
        .arg("-w")
        .arg("-f")
        .arg(dir.join("cmds"))
        .arg(&dirty)
        .output()
        .expect("run debugfs")
        .status
        .success();
    if !ok {
        return Err("debugfs could not write the journal".into());
    }
    if !sb_field(&dirty, "Filesystem features").contains("needs_recovery")
        || sb_field(&dirty, "Journal start") == "0"
    {
        return Err("debugfs left no journal to recover".into());
    }
    let before: Vec<Vec<u8>> = [a, b, c, d]
        .iter()
        .map(|&n| fs_block(&dirty, bs, n))
        .collect();

    // e2fsprogs' replay.
    let linux = dir.join("linux.img");
    std::fs::copy(&dirty, &linux).unwrap();
    let fsck = std::process::Command::new("e2fsck")
        .arg("-fy")
        .arg(&linux)
        .output()
        .expect("run e2fsck -fy");
    if !matches!(fsck.status.code(), Some(0 | 1)) {
        return Err(format!("e2fsck -fy failed: {:?}", fsck.status));
    }
    let want: Vec<Vec<u8>> = [a, b, c, d]
        .iter()
        .map(|&n| fs_block(&linux, bs, n))
        .collect();
    if want[0] != before[0] || want[1] != f1[bs as usize..] || want[2] != f2 || want[3] != before[3]
    {
        return Err("fixture: e2fsck's replay is not what the transactions say".into());
    }

    let mut report = Vec::new();
    for read_only in [false, true] {
        let image = dir.join(format!("narf-{read_only}.img"));
        std::fs::copy(&dirty, &image).unwrap();
        let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&image, 512));
        let fs = narf::mount_with(dev, "", read_only)?;
        drop(fs);
        narf_block::registry::__reset_for_test();
        let got: Vec<Vec<u8>> = [a, b, c, d]
            .iter()
            .map(|&n| fs_block(&image, bs, n))
            .collect();
        if got != want {
            return Err(format!(
                "read_only={read_only}: NARF's replay differs from e2fsck's"
            ));
        }
        if sb_field(&image, "Journal start") != "0" {
            return Err(format!("read_only={read_only}: the log is not empty"));
        }
        if read_only && sb_field(&image, "Filesystem features").contains("needs_recovery") {
            return Err("read-only mount left needs_recovery".into());
        }
        let (code, out) = check::e2fsck(&image);
        if code != 0 {
            return Err(format!("read_only={read_only}: e2fsck -fn: {out}"));
        }
        report.push(if read_only { "ro" } else { "rw" });
    }
    if !o.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!("replayed on {}", report.join(" and ")))
}

/// How a cut write stream reaches the disk.
#[derive(Clone, Copy, Debug)]
enum CutModel {
    /// Every write before the cut landed.
    Prefix,
    /// Writes after the last flush before the cut were lost, except those
    /// with FUA (a power cut with a volatile write cache).
    DropVolatile,
}

/// `log[..cut]` applied to `image` under `model`.
fn apply_cut(image: &Path, log: &[dev::Ev], cut: usize, model: CutModel) {
    use std::os::unix::fs::FileExt;
    let last_flush = log[..cut]
        .iter()
        .rposition(|e| matches!(e, dev::Ev::Flush))
        .map_or(0, |i| i + 1);
    let f = std::fs::OpenOptions::new().write(true).open(image).unwrap();
    for (i, ev) in log[..cut].iter().enumerate() {
        if let dev::Ev::Write { off, data, fua } = ev {
            if matches!(model, CutModel::DropVolatile) && i >= last_flush && !fua {
                continue;
            }
            f.write_all_at(data, *off).unwrap();
        }
    }
}

/// Transactions still to replay in `image`'s log, as e2fsprogs reads it
/// (`debugfs logdump`: the commit blocks between the tail and the end).
fn pending_commits(image: &Path) -> usize {
    let out = std::process::Command::new("debugfs")
        .args(["-R", "logdump"])
        .arg(image)
        .output()
        .expect("run debugfs logdump");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("(commit block)"))
        .count()
}

/// Whether `ev` writes a JBD2 commit block.
fn is_commit_write(ev: &dev::Ev) -> bool {
    match ev {
        dev::Ev::Write { data, fua, .. } => {
            *fua && data.len() >= 8
                && data[..4] == 0xC03B_3998u32.to_be_bytes()
                && data[4..8] == 2u32.to_be_bytes()
        }
        dev::Ev::Flush => false,
    }
}

/// [`crash_one`] over the journal formats ext4 writes: csum v3 with 64-bit
/// tags (the default); no checksums (`^metadata_csum`); 32-bit tags
/// (`^64bit`); 1 KiB blocks with the smallest journal (1024 blocks), which
/// commits often and wraps the log many times.
fn crash(o: &Opts, seed: u64) -> Result<String, String> {
    let formats: [(&str, u32, &[&str]); 4] = [
        ("csum-v3", 4096, &[]),
        (
            "no-csum",
            4096,
            &["-O", "^metadata_csum,^metadata_csum_seed"],
        ),
        ("32-bit", 4096, &["-O", "^64bit"]),
        ("1k-small-journal", 1024, &["-J", "size=1"]),
    ];
    let mut report = Vec::new();
    for (label, block_size, args) in formats {
        let summary =
            crash_one(o, seed, label, block_size, args).map_err(|e| format!("{label}: {e}"))?;
        report.push(format!("{label}: {summary}"));
    }
    Ok(report.join("; "))
}

/// A journaled workload cut short. NARF's write stream from the mount on is
/// recorded, then replayed onto the original image up to each cut: after
/// every flush (sampled), just before and just after commit blocks, and at
/// random points; each as all-landed and as lost-volatile-writes. After
/// each cut:
/// - `e2fsck -fy` may only recover the journal (anything it has to fix is a
///   failure);
/// - `e2fsck -fn` then finds nothing;
/// - a file written and fsynced before the cut, and not touched after,
///   reads back exactly (`debugfs cat`).
///
/// On cuts just after a commit block, NARF itself recovers a copy, and
/// must reach the tree e2fsck reaches. Some cuts must hold transactions
/// still to replay.
fn crash_one(
    o: &Opts,
    seed: u64,
    label: &str,
    block_size: u32,
    mkfs_args: &[&str],
) -> Result<String, String> {
    let name = format!("crash-{label}-{seed}");
    let spec = fixture::Spec {
        block_size,
        size_mib: 64,
        lib_files: 50,
        packages: 10,
        mkfs_args: mkfs_args.iter().map(|a| a.to_string()).collect(),
        ..fixture::Spec::root()
    };
    let fx = fixture::build(&o.workdir, &name, &spec, seed);
    let dir = o.workdir.join(&name);
    let base = dir.join("base.img");
    std::fs::copy(&fx.image, &base).unwrap();
    let model = Model::load_host(&fx.tree);
    let dev = Arc::new(ImageDev::open(&fx.image, 512));
    dev.set_recording(true);
    let fs = narf::mount(dev.clone() as Arc<dyn narf_block::BlockDeviceSync>)?;
    // The smallest journal gets enough operations to go round its 1024
    // blocks several times.
    let scale = if label == "1k-small-journal" { 4 } else { 1 };
    let params = Params {
        ops: (o.ops / 6).max(50) * scale,
        roots: vec!["/work".into()],
        hot_dirs: Vec::new(),
        max_file: 64 * 1024,
    };
    let mut w = Workload::new(seed, model, fs.root());
    w.run(&params)?;
    let mut rng = rng::Rng::new(seed ^ 0x5eed);
    let marker: Vec<u8> = (0..20_000).map(|_| rng.next() as u8).collect();
    host::block_on(async {
        let f = fs.root().create("marker").await?;
        let mut off = 0usize;
        while off < marker.len() {
            off += f.write(off as u64, &marker[off..]).await?;
        }
        f.fsync(false).await
    })
    .map_err(|e| format!("marker: {e:?}"))?;
    let durable = dev.log_len();
    w.run(&params)?;
    let log = dev.take_log();
    dev.set_recording(false);
    drop(w);
    drop(fs);
    narf_block::registry::__reset_for_test();

    let flushes: Vec<usize> = log
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, dev::Ev::Flush))
        .map(|(i, _)| i + 1)
        .collect();
    let commits: Vec<usize> = log
        .iter()
        .enumerate()
        .filter(|(_, e)| is_commit_write(e))
        .map(|(i, _)| i)
        .collect();
    if commits.is_empty() {
        return Err("no commit block was written".into());
    }
    // Each commit block's place in the log: a lower one than the last means
    // the log wrapped past `s_maxlen` back to `s_first`.
    let offsets: Vec<u64> = commits
        .iter()
        .map(|&i| match &log[i] {
            dev::Ev::Write { off, .. } => *off,
            dev::Ev::Flush => 0,
        })
        .collect();
    let wraps = offsets.windows(2).filter(|w| w[1] < w[0]).count();
    if label == "1k-small-journal" && wraps == 0 {
        return Err("the smallest journal never wrapped".into());
    }
    let features = sb_field(&fx.image, "Journal features");
    let format_ok = match label {
        "csum-v3" => features.contains("journal_checksum_v3") && features.contains("journal_64bit"),
        "no-csum" => !features.contains("checksum"),
        "32-bit" => !features.contains("journal_64bit") && features.contains("journal_checksum_v3"),
        _ => true,
    };
    if !format_ok {
        return Err(format!("journal written in the wrong format: {features}"));
    }
    let mut cuts: Vec<(usize, bool)> = flushes
        .iter()
        .step_by((flushes.len() / 16).max(1))
        .map(|&c| (c, false))
        .collect();
    for &c in commits.iter().step_by((commits.len() / 8).max(1)) {
        cuts.push((c, false));
        cuts.push((c + 1, true));
    }
    for _ in 0..6 {
        cuts.push((1 + (rng.next() as usize) % log.len(), false));
    }
    cuts.push((durable, false));
    cuts.push((log.len(), false));
    cuts.sort_unstable();
    cuts.dedup_by_key(|c| c.0);
    let image = dir.join("cut.img");
    let narf_image = dir.join("narf-cut.img");
    let (mut checked, mut pending, mut narf_replays) = (0usize, 0usize, 0usize);
    for &(cut, after_commit) in &cuts {
        for model in [CutModel::Prefix, CutModel::DropVolatile] {
            std::fs::copy(&base, &image).unwrap();
            apply_cut(&image, &log, cut, model);
            let to_replay = pending_commits(&image);
            pending += to_replay;
            if after_commit && matches!(model, CutModel::Prefix) {
                std::fs::copy(&image, &narf_image).unwrap();
            }
            let fsck = std::process::Command::new("e2fsck")
                .arg("-fy")
                .arg(&image)
                .output()
                .expect("run e2fsck -fy");
            let text = String::from_utf8_lossy(&fsck.stdout).into_owned()
                + &String::from_utf8_lossy(&fsck.stderr);
            // e2fsck's optional optimizations ("extent tree could be
            // shorter. Optimize?") are not repairs: Linux leaves such trees
            // too, and `e2fsck -fn` does not count them.
            let repaired = text
                .lines()
                .any(|l| (l.contains("Fix?") || l.contains("? yes")) && !l.contains("Optimize?"));
            if fsck.status.code() != Some(0) || repaired {
                return Err(format!(
                    "cut {cut}/{} {model:?}: e2fsck -fy had to repair ({:?}):\n{text}",
                    log.len(),
                    fsck.status.code()
                ));
            }
            let (code, out) = check::e2fsck(&image);
            if code != 0 {
                return Err(format!(
                    "cut {cut} {model:?}: e2fsck -fn after recovery:\n{out}"
                ));
            }
            if cut >= durable {
                let cat = std::process::Command::new("debugfs")
                    .args(["-R", "cat /marker"])
                    .arg(&image)
                    .output()
                    .expect("run debugfs cat");
                if cat.stdout != marker {
                    return Err(format!(
                        "cut {cut} {model:?}: the fsynced marker did not survive ({} bytes)",
                        cat.stdout.len()
                    ));
                }
            }
            if after_commit && matches!(model, CutModel::Prefix) {
                // NARF recovers its own log, to the tree e2fsck reached.
                let ro = Arc::new(ImageDev::open(&narf_image, 512));
                let fs = narf::mount_with(ro as Arc<dyn narf_block::BlockDeviceSync>, "", true)
                    .map_err(|e| format!("cut {cut}: NARF recovery mount: {e}"))?;
                drop(fs);
                narf_block::registry::__reset_for_test();
                let (code, out) = check::e2fsck(&narf_image);
                if code != 0 {
                    return Err(format!(
                        "cut {cut}: e2fsck -fn after NARF's recovery:\n{out}"
                    ));
                }
                let linux = check::debugfs_tree(&image, &dir.join("tree-linux"));
                let narf = check::debugfs_tree(&narf_image, &dir.join("tree-narf"));
                let d = linux.diff(&narf, 10);
                if !d.is_empty() {
                    return Err(format!(
                        "cut {cut}: NARF's recovery differs from e2fsck's:\n  {}",
                        d.join("\n  ")
                    ));
                }
                narf_replays += 1;
            }
            checked += 1;
        }
    }
    if pending == 0 {
        return Err(
            "no cut left a transaction to replay: the cuts do not exercise recovery".into(),
        );
    }
    if !o.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!(
        "{checked} cuts, {pending} pending commits replayed, {narf_replays} recovered by NARF too; {} commits, {wraps} log wraps, {} flushes",
        commits.len(),
        flushes.len()
    ))
}

/// One file of `image` as e2fsprogs reads it (`debugfs cat`), `None` if it
/// does not exist.
fn debugfs_cat(image: &Path, path: &str) -> Option<Vec<u8>> {
    let stat = std::process::Command::new("debugfs")
        .args(["-R", &format!("stat {path}")])
        .arg(image)
        .output()
        .expect("run debugfs stat");
    if String::from_utf8_lossy(&stat.stderr).contains("File not found") {
        return None;
    }
    let cat = std::process::Command::new("debugfs")
        .args(["-R", &format!("cat {path}")])
        .arg(image)
        .output()
        .expect("run debugfs cat");
    Some(cat.stdout)
}

/// Write `data` to a new file `name` under `root`.
async fn create_with(
    root: &Arc<dyn narf_filesystem::DirOps>,
    name: &str,
    data: &[u8],
) -> Result<Arc<dyn narf_filesystem::FileOps>, narf_filesystem::FsError> {
    let f = root.create(name).await?;
    let mut off = 0usize;
    while off < data.len() {
        off += f.write(off as u64, &data[off..]).await?;
    }
    Ok(f)
}

/// Nothing reaches its home location before its transaction commits, and a
/// block freed in a transaction is not reused before that commit
/// (`ext4_free_blocks` holds it until `ext4_journal_commit_callback`):
/// - `/a` (256 KiB) is written and fsynced;
/// - `/a` is unlinked and `/b`, as large, is written, without a sync.
///   NARF already sees `/b` and no `/a`; the device, read by debugfs,
///   still has `/a` intact and no `/b`. Had `/b` reused `/a`'s freed
///   blocks, `/a`'s committed bytes would be gone;
/// - after `syncfs` the device has `/b` and no `/a`, and e2fsck is clean.
fn reuse(o: &Opts, seed: u64) -> Result<String, String> {
    let name = format!("reuse-{seed}");
    let spec = fixture::Spec {
        size_mib: 64,
        lib_files: 50,
        packages: 10,
        ..fixture::Spec::root()
    };
    let fx = fixture::build(&o.workdir, &name, &spec, seed);
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
    let fs = narf::mount(dev)?;
    let root = fs.root();
    let mut rng = rng::Rng::new(seed);
    let a: Vec<u8> = (0..256 * 1024).map(|_| rng.next() as u8).collect();
    let b: Vec<u8> = (0..256 * 1024).map(|_| rng.next() as u8).collect();
    host::block_on(async { create_with(&root, "a", &a).await?.fsync(false).await })
        .map_err(|e| format!("write /a: {e:?}"))?;
    if debugfs_cat(&fx.image, "/a").as_deref() != Some(&a[..]) {
        return Err("fsynced /a is not on the device".into());
    }
    host::block_on(async {
        root.unlink("a").await?;
        create_with(&root, "b", &b).await.map(|_| ())
    })
    .map_err(|e| format!("unlink /a, write /b: {e:?}"))?;
    let seen = host::block_on(async {
        let f = root.lookup_async("b").await?;
        narf::read_all(&f).await
    })
    .map_err(|e| format!("read /b: {e:?}"))?;
    if seen != b || host::block_on(root.lookup_async("a")).is_ok() {
        return Err("NARF does not see its own uncommitted changes".into());
    }
    if debugfs_cat(&fx.image, "/a").as_deref() != Some(&a[..]) {
        return Err(
            "before the commit, the device lost /a's bytes: a freed block was reused".into(),
        );
    }
    if debugfs_cat(&fx.image, "/b").is_some() {
        return Err("before the commit, /b is already on the device".into());
    }
    host::block_on(root.syncfs()).map_err(|e| format!("syncfs: {e:?}"))?;
    if debugfs_cat(&fx.image, "/a").is_some()
        || debugfs_cat(&fx.image, "/b").as_deref() != Some(&b[..])
    {
        return Err("after syncfs the device does not have the new state".into());
    }
    drop(root);
    drop(fs);
    narf_block::registry::__reset_for_test();
    journal_left_clean(&fx.image)?;
    let (code, out) = check::e2fsck(&fx.image);
    if code != 0 {
        return Err(format!("e2fsck -fn:\n{out}"));
    }
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(&name));
    }
    Ok("committed state held until the commit".into())
}

/// A device write fails in the middle of a commit (`jbd2_journal_abort`):
/// `syncfs` fails, the volume refuses further writes (EROFS), and the
/// filesystem is left needing recovery. `e2fsck -fy` then recovers the last
/// committed state without a repair: the fsynced file is intact, the
/// uncommitted one absent.
fn abort(o: &Opts, seed: u64) -> Result<String, String> {
    let name = format!("abort-{seed}");
    let spec = fixture::Spec {
        size_mib: 64,
        lib_files: 50,
        packages: 10,
        ..fixture::Spec::root()
    };
    let fx = fixture::build(&o.workdir, &name, &spec, seed);
    let dev = Arc::new(ImageDev::open(&fx.image, 512));
    let fs = narf::mount(dev.clone() as Arc<dyn narf_block::BlockDeviceSync>)?;
    let root = fs.root();
    let mut rng = rng::Rng::new(seed);
    let kept: Vec<u8> = (0..64 * 1024).map(|_| rng.next() as u8).collect();
    host::block_on(async { create_with(&root, "kept", &kept).await?.fsync(false).await })
        .map_err(|e| format!("write /kept: {e:?}"))?;
    host::block_on(async {
        create_with(&root, "lost", &kept[..4096]).await?;
        root.mkdir("lostdir").await.map(|_| ())
    })
    .map_err(|e| format!("uncommitted changes: {e:?}"))?;
    // The commit's third write and every one after it fail.
    dev.fail_writes_after(2);
    if host::block_on(root.syncfs()).is_ok() {
        return Err("syncfs succeeded on a failing device".into());
    }
    if !matches!(
        host::block_on(root.create("after")),
        Err(narf_filesystem::FsError::ReadOnly)
    ) {
        return Err("an aborted journal must refuse writes with EROFS".into());
    }
    drop(root);
    drop(fs);
    narf_block::registry::__reset_for_test();
    if !sb_field(&fx.image, "Filesystem features").contains("needs_recovery") {
        return Err("an aborted journal must leave needs_recovery".into());
    }
    let fsck = std::process::Command::new("e2fsck")
        .arg("-fy")
        .arg(&fx.image)
        .output()
        .expect("run e2fsck -fy");
    let text = String::from_utf8_lossy(&fsck.stdout).into_owned();
    if fsck.status.code() != Some(0) || text.contains("Fix?") {
        return Err(format!(
            "e2fsck -fy after the abort ({:?}):\n{text}",
            fsck.status.code()
        ));
    }
    if debugfs_cat(&fx.image, "/kept").as_deref() != Some(&kept[..])
        || debugfs_cat(&fx.image, "/lost").is_some()
        || debugfs_cat(&fx.image, "/lostdir").is_some()
    {
        return Err("recovery did not land on the last committed state".into());
    }
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(&name));
    }
    Ok("aborted, recovered to the last commit".into())
}

/// Inode numbers in `image`'s orphan file (`debugfs cat <inode>`), and the
/// head of its orphan list (`s_last_orphan`).
fn orphan_record(image: &Path) -> (Vec<u32>, u32) {
    let bs: usize = sb_field(image, "Block size").parse().unwrap();
    let mut entries = Vec::new();
    if let Ok(inode) = sb_field(image, "Orphan file inode").parse::<u32>() {
        let cat = std::process::Command::new("debugfs")
            .args(["-R", &format!("cat <{inode}>")])
            .arg(image)
            .output()
            .expect("run debugfs cat");
        for block in cat.stdout.chunks(bs) {
            for e in block[..block.len().saturating_sub(8)].chunks_exact(4) {
                let ino = u32::from_le_bytes(e.try_into().unwrap());
                if ino != 0 {
                    entries.push(ino);
                }
            }
        }
    }
    let list = sb_field(image, "First orphan inode").parse().unwrap_or(0);
    (entries, list)
}

/// `debugfs testi`: whether `ino` is allocated in the inode bitmap.
fn inode_in_use(image: &Path, ino: u32) -> bool {
    let out = std::process::Command::new("debugfs")
        .args(["-R", &format!("testi <{ino}>")])
        .arg(image)
        .output()
        .expect("run debugfs testi");
    String::from_utf8_lossy(&out.stdout).contains("is marked in use")
}

/// `debugfs ls -l /`: the inode number of every root entry named
/// `prefix*`.
fn root_inos(image: &Path, prefix: &str) -> std::collections::BTreeMap<String, u32> {
    let out = std::process::Command::new("debugfs")
        .args(["-R", "ls -l /"])
        .arg(image)
        .output()
        .expect("run debugfs ls");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let ino = words.next()?.parse().ok()?;
            let name = words.last()?;
            name.starts_with(prefix).then(|| (name.to_string(), ino))
        })
        .collect()
}

/// The physical block of logical block 0 of inode `ino` (`debugfs bmap`).
fn first_block(image: &Path, ino: u32) -> u64 {
    let out = std::process::Command::new("debugfs")
        .args(["-R", &format!("bmap <{ino}> 0")])
        .arg(image)
        .output()
        .expect("run debugfs bmap");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("a block number")
}

fn copy_image(dir: &Path, from: &Path, name: &str) -> PathBuf {
    let image = dir.join(format!("{name}.img"));
    std::fs::copy(from, &image).unwrap();
    image
}

/// Mount `image` with NARF (`read_only`, mount `options`) and unmount it.
fn mount_cycle(image: &Path, options: &str, read_only: bool) -> Result<(), String> {
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(image, 512));
    let fs = narf::mount_with(dev, options, read_only)?;
    drop(fs);
    narf_block::registry::__reset_for_test();
    Ok(())
}

/// A recovery of `crashed` (a copy of it) by `how`, judged by e2fsck:
/// afterwards every inode of `inos` is free, nothing is recorded as an
/// orphan, and `e2fsck -fn` is clean.
fn recover_orphans(dir: &Path, crashed: &Path, inos: &[u32], how: &str) -> Result<(), String> {
    let image = copy_image(dir, crashed, &format!("recover-{how}"));
    match how {
        "narf-rw" | "narf-ro" => {
            mount_cycle(&image, "", how == "narf-ro")?;
            journal_left_clean(&image)?;
        }
        _ => {
            let fsck = std::process::Command::new("e2fsck")
                .arg("-fy")
                .arg(&image)
                .output()
                .expect("run e2fsck -fy");
            if !matches!(fsck.status.code(), Some(0 | 1)) {
                return Err(format!("{how}: e2fsck -fy exited {:?}", fsck.status.code()));
            }
        }
    }
    let (entries, list) = orphan_record(&image);
    let still: Vec<u32> = inos
        .iter()
        .copied()
        .filter(|&i| inode_in_use(&image, i))
        .collect();
    if !entries.is_empty() || list != 0 || !still.is_empty() {
        return Err(format!(
            "{how}: orphans not released (file {entries:?}, list {list}, in use {still:?})"
        ));
    }
    let (code, out) = check::e2fsck(&image);
    if code != 0 {
        return Err(format!("{how}: e2fsck -fn:\n{out}"));
    }
    Ok(())
}

/// The orphan record (`fs/ext4/orphan.c`) in three layouts: the orphan
/// file, the `s_last_orphan` list (`^orphan_file`), and an orphan file of
/// one block that overflows onto the list.
/// - Files kept open are unlinked and the change synced. On the device
///   each inode then has no link and is recorded as an orphan, in the same
///   transaction as its unlink. A snapshot here is a crash with them open.
/// - With them open, remount read-only is EBUSY (`s_remove_count`).
/// - Closing them releases them: the record is cleared and the inodes freed.
/// - The snapshot is recovered by a NARF read-write mount, a NARF read-only
///   mount (Linux's "orphan cleanup on readonly fs", which also clears
///   `RECOVER`/`ORPHAN_PRESENT`) and `e2fsck -fy`. Each frees the inodes,
///   leaves no record, and `e2fsck -fn` is clean.
/// - Then the rules around it: a write-protected device (`noload`) skips the
///   cleanup and writes nothing; `ERROR_FS` clears the list on a read-write
///   mount and keeps it on a read-only one, which a remount read-write then
///   refuses (EINVAL); an orphan file entry left on a read-only mount with
///   errors fails it (EUCLEAN); an orphan file block with a bad magic or
///   checksum fails the mount (EIO).
///
/// Last, a truncate Linux left on the list (`i_size` cut, blocks still
/// mapped) is finished by a NARF mount, tail of the EOF block zeroed, and a
/// list naming a free inode is a filesystem error that ends the list.
fn orphan(o: &Opts, seed: u64) -> Result<String, String> {
    use narf_filesystem::sb_flags::RDONLY;
    let mut report = Vec::new();
    for layout in ["file", "list", "overflow"] {
        let name = format!("orphan-{seed}-{layout}");
        let (block_size, mkfs_args, count) = match layout {
            "file" => (4096, Vec::new(), 1),
            "list" => (4096, vec!["-O".into(), "^orphan_file".into()], 1),
            // One block of (1024 - 8) / 4 = 254 slots, then the list.
            _ => (
                1024,
                vec!["-E".into(), "root_owner=0:0,orphan_file_size=1".into()],
                256,
            ),
        };
        let spec = fixture::Spec {
            block_size,
            size_mib: 64,
            lib_files: 50,
            packages: 10,
            mkfs_args,
            ..fixture::Spec::root()
        };
        let fx = fixture::build(&o.workdir, &name, &spec, seed);
        let dir = o.workdir.join(&name);
        let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
        let fs = narf::mount(dev)?;
        let root = fs.root();
        let mut rng = rng::Rng::new(seed);
        let data: Vec<u8> = (0..if count == 1 { 200 * 1024 } else { 3000 })
            .map(|_| rng.next() as u8)
            .collect();
        let names: Vec<String> = (0..count).map(|i| format!("held{i:03}")).collect();
        let held = host::block_on(async {
            let mut held = Vec::new();
            for name in &names {
                let f = create_with(&root, name, &data).await?;
                f.fsync(false).await?;
                held.push(f);
            }
            root.syncfs().await?;
            Ok::<_, narf_filesystem::FsError>(held)
        })
        .map_err(|e| format!("write the held files: {e:?}"))?;
        let by_name = root_inos(&fx.image, "held");
        let inos: Vec<u32> = names
            .iter()
            .map(|n| by_name.get(n).copied().ok_or(format!("no inode for /{n}")))
            .collect::<Result<_, _>>()?;
        host::block_on(async {
            for name in &names {
                root.unlink(name).await?;
            }
            root.syncfs().await
        })
        .map_err(|e| format!("unlink the held files: {e:?}"))?;
        match host::block_on(fs.reconfigure_sb_async(RDONLY, RDONLY, "")) {
            Err(narf_filesystem::FsError::Busy) => {}
            other => {
                return Err(format!(
                    "remount read-only with unlinked files open: {other:?}, not EBUSY"
                ))
            }
        }
        let (mut entries, list) = orphan_record(&fx.image);
        let recorded = match layout {
            "file" => entries == inos && list == 0,
            "list" => entries.is_empty() && list == inos[0],
            _ => {
                // The first 254 fill the file; the rest go on the list,
                // newest first, linked through `i_dtime`.
                entries.sort_unstable();
                let mut file = inos[..254].to_vec();
                file.sort_unstable();
                entries == file && list == inos[255]
            }
        };
        let in_use = inos.iter().all(|&i| inode_in_use(&fx.image, i));
        if !recorded || !in_use {
            return Err(format!(
                "{layout}: open unlinked inodes {inos:?} not recorded: file {entries:?}, list {list}, all in use {in_use}"
            ));
        }
        let crashed = copy_image(&dir, &fx.image, "crashed");
        // The last close releases them.
        drop(held);
        host::block_on(root.syncfs()).map_err(|e| format!("syncfs: {e:?}"))?;
        let (entries, list) = orphan_record(&fx.image);
        let still: Vec<u32> = inos
            .iter()
            .copied()
            .filter(|&i| inode_in_use(&fx.image, i))
            .collect();
        if !entries.is_empty() || list != 0 || !still.is_empty() {
            return Err(format!(
                "{layout}: after the close: file {entries:?}, list {list}, in use {still:?}"
            ));
        }
        drop(root);
        drop(fs);
        narf_block::registry::__reset_for_test();
        journal_left_clean(&fx.image)?;
        let (code, out) = check::e2fsck(&fx.image);
        if code != 0 {
            return Err(format!("{layout}: e2fsck -fn after the release:\n{out}"));
        }
        for how in ["narf-rw", "narf-ro", "e2fsck"] {
            recover_orphans(&dir, &crashed, &inos, how).map_err(|e| format!("{layout}: {e}"))?;
        }
        match layout {
            "list" => orphan_list_rules(&dir, &crashed, inos[0])?,
            "file" => orphan_file_rules(&dir, &crashed, &fx.image)?,
            _ => {}
        }
        report.push(layout);
        if !o.keep {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    orphan_rmdir(o, seed)?;
    report.push("rmdir while open");
    orphan_truncate(o, seed)?;
    report.push("interrupted truncate");
    Ok(report.join(", "))
}

/// `rmdir` of a directory still open (a process's cwd), with and without an
/// orphan file: `ext4_rmdir` empties it and records it as an orphan; a name
/// cannot be created in it (ENOENT); the last reference frees it, with the
/// group's directory count. A crash while it is open recovers as a file
/// does.
fn orphan_rmdir(o: &Opts, seed: u64) -> Result<(), String> {
    for orphan_file in [true, false] {
        let name = format!(
            "orphan-{seed}-rmdir-{}",
            if orphan_file { "file" } else { "list" }
        );
        let spec = fixture::Spec {
            size_mib: 64,
            lib_files: 50,
            packages: 10,
            mkfs_args: if orphan_file {
                Vec::new()
            } else {
                vec!["-O".into(), "^orphan_file".into()]
            },
            ..fixture::Spec::root()
        };
        let fx = fixture::build(&o.workdir, &name, &spec, seed);
        let dir = o.workdir.join(&name);
        let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
        let fs = narf::mount(dev)?;
        let root = fs.root();
        let gone = host::block_on(async {
            let gone = root.mkdir("gone").await?;
            root.syncfs().await?;
            Ok::<_, narf_filesystem::FsError>(gone)
        })
        .map_err(|e| format!("mkdir /gone: {e:?}"))?;
        let ino = *root_inos(&fx.image, "gone")
            .get("gone")
            .ok_or("no inode for /gone")?;
        host::block_on(async {
            root.rmdir("gone").await?;
            root.syncfs().await
        })
        .map_err(|e| format!("rmdir /gone: {e:?}"))?;
        let (entries, list) = orphan_record(&fx.image);
        let recorded = if orphan_file {
            entries == [ino] && list == 0
        } else {
            entries.is_empty() && list == ino
        };
        if !recorded || !inode_in_use(&fx.image, ino) {
            return Err(format!(
                "rmdir of an open directory {ino} not recorded: file {entries:?}, list {list}"
            ));
        }
        match host::block_on(gone.create("x")) {
            Err(narf_filesystem::FsError::NotFound) => {}
            other => {
                return Err(format!(
                    "create in a removed directory: {:?}, not ENOENT",
                    other.map(|_| "created")
                ))
            }
        }
        let crashed = copy_image(&dir, &fx.image, "crashed");
        drop(gone);
        host::block_on(root.syncfs()).map_err(|e| format!("syncfs: {e:?}"))?;
        let (entries, list) = orphan_record(&fx.image);
        if !entries.is_empty() || list != 0 || inode_in_use(&fx.image, ino) {
            return Err(format!(
                "the removed directory {ino} was not released: file {entries:?}, list {list}"
            ));
        }
        drop(root);
        drop(fs);
        narf_block::registry::__reset_for_test();
        journal_left_clean(&fx.image)?;
        let (code, out) = check::e2fsck(&fx.image);
        if code != 0 {
            return Err(format!(
                "e2fsck -fn after the removed directory's release:\n{out}"
            ));
        }
        for how in ["narf-rw", "narf-ro", "e2fsck"] {
            recover_orphans(&dir, &crashed, &[ino], how).map_err(|e| format!("rmdir: {e}"))?;
        }
        if !o.keep {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    Ok(())
}

/// The list snapshot `crashed` (inode `ino` on it) under Linux's rules.
fn orphan_list_rules(dir: &Path, crashed: &Path, ino: u32) -> Result<(), String> {
    use narf_filesystem::sb_flags::RDONLY;
    // A write-protected device, journal not loaded: nothing is written.
    let image = copy_image(dir, crashed, "ro-device");
    let before = std::fs::read(&image).unwrap();
    {
        let dev = ImageDev::open(&image, 512);
        dev.set_read_only(true);
        let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(dev);
        let fs = narf::mount_with(dev, "noload", true)?;
        drop(fs);
        narf_block::registry::__reset_for_test();
    }
    if std::fs::read(&image).unwrap() != before {
        return Err("a write-protected device was written".into());
    }
    // `ERROR_FS`, read-write: the list is cleared, the inode left to e2fsck.
    let image = copy_image(dir, crashed, "errors-rw");
    debugfs_w(&image, "ssv state 3");
    mount_cycle(&image, "", false)?;
    if orphan_record(&image).1 != 0 || !inode_in_use(&image, ino) {
        return Err(
            "with errors a read-write mount must clear the list and release nothing".into(),
        );
    }
    // `ERROR_FS`, read-only: the list stays; recovery still completes.
    let image = copy_image(dir, crashed, "errors-ro");
    debugfs_w(&image, "ssv state 3");
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&image, 512));
    let fs = narf::mount_with(dev, "", true)?;
    if orphan_record(&image).1 != ino {
        return Err("with errors a read-only mount must keep the list".into());
    }
    if sb_field(&image, "Filesystem features").contains("needs_recovery") {
        return Err("a read-only mount must complete the recovery".into());
    }
    // An unprocessed list: no remount read-write.
    match host::block_on(fs.reconfigure_sb_async(0, RDONLY, "")) {
        Err(narf_filesystem::FsError::InvalidData) => {}
        other => {
            return Err(format!(
                "remount read-write over an orphan list: {other:?}, not EINVAL"
            ))
        }
    }
    drop(fs);
    narf_block::registry::__reset_for_test();
    Ok(())
}

/// The orphan file snapshot `crashed`, and the released image `clean`,
/// under Linux's rules.
fn orphan_file_rules(dir: &Path, crashed: &Path, clean: &Path) -> Result<(), String> {
    use std::os::unix::fs::FileExt;
    // Read-only with errors: no cleanup, and an orphan file that is not
    // empty fails the mount ("Orphan file not empty on read-only fs").
    let image = copy_image(dir, crashed, "errors-ro");
    debugfs_w(&image, "ssv state 3");
    match mount_cycle(&image, "", true) {
        Err(e) if e.contains("Corrupted") => {}
        other => {
            return Err(format!(
                "read-only with errors and an orphan: {other:?}, not EUCLEAN"
            ))
        }
    }
    // A damaged orphan file block fails the mount with EIO.
    let bs: u64 = sb_field(clean, "Block size").parse().unwrap();
    let orphan_ino: u32 = sb_field(clean, "Orphan file inode").parse().unwrap();
    let block = first_block(clean, orphan_ino);
    for (what, at, bytes) in [
        ("magic", bs - 8, [0xde, 0xad, 0xbe, 0xef]),
        ("checksum", 0, [0x0d, 0, 0, 0]),
    ] {
        let image = copy_image(dir, clean, &format!("bad-{what}"));
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&image)
            .unwrap();
        f.write_all_at(&bytes, block * bs + at).unwrap();
        drop(f);
        match mount_cycle(&image, "", false) {
            Err(e) if e.contains("Io") => {}
            other => {
                return Err(format!(
                    "an orphan block with a bad {what}: {other:?}, not EIO"
                ))
            }
        }
    }
    Ok(())
}

/// A truncate Linux left on the orphan list, then a list naming a free
/// inode.
fn orphan_truncate(o: &Opts, seed: u64) -> Result<(), String> {
    let name = format!("orphan-{seed}-truncate");
    let spec = fixture::Spec {
        size_mib: 64,
        lib_files: 50,
        packages: 10,
        ..fixture::Spec::root()
    };
    let fx = fixture::build(&o.workdir, &name, &spec, seed);
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
    let fs = narf::mount(dev)?;
    let mut rng = rng::Rng::new(seed ^ 7);
    let data: Vec<u8> = (0..64 * 1024).map(|_| rng.next() as u8).collect();
    host::block_on(async {
        create_with(&fs.root(), "t", &data)
            .await?
            .fsync(false)
            .await
    })
    .map_err(|e| format!("write /t: {e:?}"))?;
    drop(fs);
    narf_block::registry::__reset_for_test();
    let ino = *root_inos(&fx.image, "t")
        .get("t")
        .ok_or("no inode for /t")?;
    debugfs_w(&fx.image, "sif /t size 100");
    debugfs_w(&fx.image, &format!("ssv last_orphan {ino}"));
    mount_cycle(&fx.image, "", false)?;
    let (_, list) = orphan_record(&fx.image);
    if list != 0 || debugfs_cat(&fx.image, "/t").as_deref() != Some(&data[..100]) {
        return Err("the truncate on the orphan list was not finished".into());
    }
    let (code, out) = check::e2fsck(&fx.image);
    if code != 0 {
        return Err(format!("e2fsck -fn after finishing the truncate:\n{out}"));
    }
    // The rest of the EOF block is zero (`ext4_block_truncate_page`).
    let bs: usize = sb_field(&fx.image, "Block size").parse().unwrap();
    debugfs_w(&fx.image, &format!("sif /t size {bs}"));
    let grown = debugfs_cat(&fx.image, "/t").unwrap_or_default();
    if grown.len() != bs || grown[..100] != data[..100] || grown[100..].iter().any(|&b| b != 0) {
        return Err("the bytes past the truncated EOF were not zeroed".into());
    }
    // A list naming a free inode: "bad orphan inode", an error, list ended.
    let free = sb_field(&fx.image, "Inode count").parse::<u32>().unwrap();
    debugfs_w(&fx.image, &format!("ssv last_orphan {free}"));
    mount_cycle(&fx.image, "", false)?;
    if orphan_record(&fx.image).1 != 0 || !sb_field(&fx.image, "Filesystem state").contains("error")
    {
        return Err("a bad orphan inode must end the list with an error recorded".into());
    }
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(&name));
    }
    Ok(())
}

fn main() {
    let o = parse_args();
    host::init();
    std::fs::create_dir_all(&o.workdir).unwrap();
    type Scenario = fn(&Opts, u64) -> Result<String, String>;
    let all: [(&str, Scenario); 11] = [
        ("baseline", baseline),
        ("lifecycle", lifecycle),
        ("gate", gate),
        ("uninit", uninit),
        ("htree", htree),
        ("extents", extents),
        ("replay", replay),
        ("crash", crash),
        ("reuse", reuse),
        ("abort", abort),
        ("orphan", orphan),
    ];
    let mut failed = 0;
    for (name, run) in all {
        if !o.scenarios.is_empty() && !o.scenarios.iter().any(|s| s == name) {
            continue;
        }
        for seed in o.seed..o.seed + o.seeds {
            let started = std::time::Instant::now();
            match run(&o, seed) {
                Ok(summary) => println!(
                    "PASS {name} seed={seed} ({:.1}s) {summary}",
                    started.elapsed().as_secs_f64()
                ),
                Err(e) => {
                    failed += 1;
                    println!("FAIL {name} seed={seed}: {e}");
                }
            }
        }
    }
    if failed > 0 {
        println!("{failed} run(s) failed");
        std::process::exit(1);
    }
    println!("all runs passed");
}
