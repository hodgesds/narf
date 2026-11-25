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
  --scenario LIST   comma-separated subset of: baseline (default all)
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
    drop(fs);
    narf_block::registry::__reset_for_test();
    verdict(
        &fx.image,
        &w.model,
        &o.workdir.join(format!("baseline-{seed}/rdump")),
    )?;
    if !o.keep {
        let _ = std::fs::remove_dir_all(o.workdir.join(format!("baseline-{seed}")));
    }
    Ok(format!("{:?}", w.counts))
}

fn main() {
    let o = parse_args();
    host::init();
    std::fs::create_dir_all(&o.workdir).unwrap();
    type Scenario = fn(&Opts, u64) -> Result<String, String>;
    let all: [(&str, Scenario); 1] = [("baseline", baseline)];
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
