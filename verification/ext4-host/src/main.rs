//! Host-side (no QEMU) write harness for NARF's ext4 driver.
//!
//! Runs the driver in a std process against image files made by the real
//! `mkfs.ext4 -d` from a CachyOS-shaped tree, applies a seeded random
//! workload mirrored into a model, and judges the result with Linux's
//! userspace: `e2fsck -fn` must find nothing, `debugfs rdump` must see the
//! model's tree, and a fresh NARF mount must read it back. `cargo xtask
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
  --scenario LIST   comma-separated subset of: baseline,lifecycle,gate,uninit
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
fn verdict(image: &Path, expected: &Model, scratch: &Path) -> Result<(), String> {
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

/// The superblock across a root-rw mount: "not clean" while mounted, one
/// more mount counted, "clean" again after a remount read-only, and e2fsck
/// finds nothing.
fn lifecycle(o: &Opts, seed: u64) -> Result<String, String> {
    use narf_filesystem::sb_flags::RDONLY;
    let name = format!("lifecycle-{seed}");
    let fx = fixture::build(&o.workdir, &name, &fixture::Spec::root(), seed);
    let model = Model::load_host(&fx.tree);
    let mounts_before: u32 = sb_field(&fx.image, "Mount count").parse().unwrap_or(0);
    let uuid = narf::image_uuid(&fx.image);
    let dev: Arc<dyn narf_block::BlockDeviceSync> = Arc::new(ImageDev::open(&fx.image, 512));
    let fs = narf::mount_root_rw(dev, &uuid).map_err(|e| format!("root-rw mount: {e:?}"))?;
    let dirty = sb_field(&fx.image, "Filesystem state");
    let mounts: u32 = sb_field(&fx.image, "Mount count").parse().unwrap_or(0);
    if dirty != "not clean" || mounts != mounts_before + 1 {
        return Err(format!(
            "mounted: state {dirty:?}, mount count {mounts} (was {mounts_before})"
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
    if sb_field(&fx.image, "Filesystem state") != "not clean" {
        return Err("syncfs must not mark the filesystem clean".into());
    }
    host::block_on(fs.reconfigure_sb_async(RDONLY, RDONLY, ""))
        .map_err(|e| format!("remount read-only: {e:?}"))?;
    let clean = sb_field(&fx.image, "Filesystem state");
    if clean != "clean" {
        return Err(format!("after remount read-only the state is {clean:?}"));
    }
    let (model, counts) = (w.model.clone(), format!("{:?}", w.counts));
    drop(w);
    drop(fs);
    narf_block::registry::__reset_for_test();
    verdict(&fx.image, &model, &o.workdir.join(format!("{name}/rdump")))?;
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(&name));
    }
    Ok(counts)
}

/// root-rw refuses what e2fsck has not checked: an unclean filesystem, one
/// with recorded errors, one with an orphan list. Each read-write request
/// fails with EROFS and leaves the image bit-identical.
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
        ("ssv last_orphan 12", "an orphan list"),
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
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(&name));
    }
    Ok("3 refusals".into())
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

fn main() {
    let o = parse_args();
    host::init();
    std::fs::create_dir_all(&o.workdir).unwrap();
    type Scenario = fn(&Opts, u64) -> Result<String, String>;
    let all: [(&str, Scenario); 4] = [
        ("baseline", baseline),
        ("lifecycle", lifecycle),
        ("gate", gate),
        ("uninit", uninit),
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
