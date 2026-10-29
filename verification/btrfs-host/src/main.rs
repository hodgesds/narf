//! Host-side (no QEMU) root-rw harness for NARF's btrfs driver.
//!
//! Runs the driver in a std process against image files: CachyOS-shaped
//! fixtures made with `mkfs.btrfs --rootdir`, and the committed Linux
//! snapshot fixture. Each scenario mounts the image exactly as a
//! `narf.disks=root-rw` boot does, runs a seeded random workload mirrored
//! into a model, then judges the result with Linux userspace (`btrfs check`,
//! `btrfs restore`), a fresh NARF remount, and a crash-consistency replay of
//! the recorded write/flush stream. See `--help`; `cargo xtask btrfs-host-rw`
//! is the usual entry point.

mod crash;
mod dev;
mod fixture;
mod host;
mod linux;
mod model;
mod narf;
mod workload;

#[cfg(test)]
mod file_loading_tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::dev::RecDev;
use crate::model::{diff, summarize, Cmp, FlatTree};
use crate::workload::{Op, Params, Sub, Workload};

const USAGE: &str = "\
narf-btrfs-host — host-side root-rw btrfs harness (no QEMU)

USAGE: narf-btrfs-host [OPTIONS]

  --seed N          first workload seed (default 1)
  --seeds N         number of seeds per scenario (default 2)
  --ops N           operations in the `root` scenario (default 3000; the
                    others scale from it)
  --cuts N          crash cut points in the `root` scenario (default 48; the
                    others scale from it; 0 disables the crash pass)
  --exhaustive      crash-test every flush boundary plus two random cuts per
                    flush window (slow)
  --scenario LIST   comma-separated subset of: regress,root,snapshots,lba4k,gate
                    (default all)
  --jobs N          concurrent `btrfs check` processes in the crash pass
                    (default 3)
  --workdir DIR     scratch directory (default target/btrfs-host)
  --keep            keep images of passing runs
  -v                print the op trace of a failing run
";

/// The default selection (`regress` = every `regress-*` case).
pub const SCENARIOS: [&str; 5] = ["regress", "root", "snapshots", "lba4k", "gate"];
/// Names `--scenario` also accepts.
const REGRESS: [&str; 3] = [
    "regress-zstd-tail",
    "regress-inline-falloc",
    "regress-atomic",
];

#[derive(Clone, Debug)]
struct Args {
    seed: u64,
    seeds: u64,
    ops: usize,
    cuts: usize,
    exhaustive: bool,
    scenarios: Vec<String>,
    jobs: usize,
    workdir: PathBuf,
    keep: bool,
    verbose: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        seed: 1,
        seeds: 2,
        ops: 3000,
        cuts: 48,
        exhaustive: false,
        scenarios: SCENARIOS.map(String::from).to_vec(),
        jobs: 3,
        workdir: Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/btrfs-host"),
        keep: false,
        verbose: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        let num = |s: String| s.parse::<u64>().map_err(|e| format!("{s}: {e}"));
        match arg.as_str() {
            "--seed" => a.seed = num(val("--seed")?)?,
            "--seeds" => a.seeds = num(val("--seeds")?)?.max(1),
            "--ops" => a.ops = num(val("--ops")?)? as usize,
            "--cuts" => a.cuts = num(val("--cuts")?)? as usize,
            "--exhaustive" => a.exhaustive = true,
            "--scenario" => a.scenarios = val("--scenario")?.split(',').map(String::from).collect(),
            "--jobs" => a.jobs = num(val("--jobs")?)?.max(1) as usize,
            "--workdir" => a.workdir = PathBuf::from(val("--workdir")?),
            "--keep" => a.keep = true,
            "-v" | "--verbose" => a.verbose = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    for s in &a.scenarios {
        if !SCENARIOS.contains(&s.as_str()) && !REGRESS.contains(&s.as_str()) {
            return Err(format!("unknown scenario {s}"));
        }
    }
    Ok(a)
}

/// The full Linux-side comparison: permissions (restore `-m`) and xattrs
/// (`-x`) included.
const FULL: Cmp = Cmp {
    perms: true,
    xattrs: true,
    dir_perms: true,
};

struct Scenario {
    name: &'static str,
    lba: u32,
    ops: usize,
    cuts: usize,
    source: Source,
    params: Params,
    /// A fixed op list instead of the random workload (regression cases);
    /// its crash pass is exhaustive.
    script: Option<fn() -> Vec<Op>>,
}

/// Where the pristine image comes from.
enum Source {
    Mkfs {
        populate: fn(&Path, u64, usize),
        scale: usize,
        size: u64,
    },
    Sparse(&'static str),
}

/// Compare and describe, `Err` on any difference.
fn expect_same(what: &str, want: &FlatTree, got: &FlatTree, cmp: Cmp) -> Result<(), String> {
    let d = diff(want, got, cmp, 20);
    if d.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{what}: {} differences:\n  {}",
            d.len(),
            d.join("\n  ")
        ))
    }
}

/// Remove nested subvolumes from a `btrfs restore -r` tree: restore descends
/// into a nested plain subvolume (and leaves an empty directory for a nested
/// snapshot), while NARF's walk stops at every subvolume boundary. Each
/// subvolume is compared on its own (`restore -r <its id>`).
fn drop_nested(t: &mut FlatTree, nested: &[String]) {
    for n in nested {
        let prefix = format!("{n}/");
        t.retain(|k, _| k != n && !k.starts_with(&prefix));
    }
}

fn mount_subvolid(
    id: u64,
) -> Result<Arc<dyn narf_filesystem::FsInstance>, narf_filesystem::FsError> {
    let fstype =
        narf_filesystem::lookup_fstype("btrfs").ok_or(narf_filesystem::FsError::NotFound)?;
    let source = format!("/dev/{}", narf::PART);
    fstype.init(&narf_filesystem::MountRequest {
        fs_type: "btrfs",
        source: &source,
        options: &format!("ro,subvolid={id}"),
        uid: 0,
        gid: 0,
        umask: 0o022,
        initial_namespace: true,
        read_only: true,
    })
}

fn run_scenario(sc: &Scenario, seed: u64, args: &Args) -> Result<String, String> {
    let t0 = Instant::now();
    let dir = args.workdir.join(format!("{}-{seed}", sc.name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pristine = dir.join("pristine.img");
    match &sc.source {
        Source::Mkfs {
            populate,
            scale,
            size,
        } => {
            let rootdir = dir.join("rootdir");
            populate(&rootdir, seed, *scale);
            fixture::mkfs(
                &pristine,
                &rootdir,
                &fixture::MkfsSpec {
                    uuid: &format!(
                        "c4c405ee-0000-4a11-9e57-{:012x}",
                        0xb7f5_0000_0000u64 + seed
                    ),
                    size: *size,
                    nodesize: 16384,
                    csum: "crc32c",
                    features: "block-group-tree,free-space-tree,no-holes",
                },
            )?;
            let _ = std::fs::remove_dir_all(&rootdir);
        }
        Source::Sparse(name) => fixture::unsparse(&fixture::testdata().join(name), &pristine),
    }
    linux::check(&pristine, true).map_err(|e| format!("pristine fixture: {e}"))?;
    let (fsid, nodesize, base_gen) = dev::image_identity(&pristine);
    let subvols = linux::subvolumes(&pristine)?;
    let at_id = linux::subvol_id(&subvols, "@").ok_or("fixture has no @")?;
    let home_id = linux::subvol_id(&subvols, "@home").ok_or("fixture has no @home")?;
    let workload_ids = [at_id, home_id];
    // Every other subvolume (the snapshots) must come through untouched.
    let mut pre_snaps = BTreeMap::new();
    for s in subvols.iter().filter(|s| !workload_ids.contains(&s.id)) {
        let t = linux::restore(&pristine, s.id, &dir.join(format!("restore-pre-{}", s.id)))?;
        pre_snaps.insert(s.id, (s.name.clone(), t));
    }
    let chunks_before = linux::chunk_counts(&pristine);

    let work = dir.join("work.img");
    linux::clone_file(&pristine, &work);
    let dev = Arc::new(RecDev::open(&work, sc.lba, fsid, nodesize));
    dev.set_recording(sc.cuts > 0);
    narf::register_root(dev.clone(), &fsid)?;
    let views = narf::mount_root_rw(&fsid, "@", &["@home"])?;

    // NARF's initial view must equal Linux's before anything is written.
    let mut subs = Vec::new();
    for (v, (name, id)) in views.iter().zip([("@", at_id), ("@home", home_id)]) {
        let root = v.root();
        let (model, nested) = workload::model_from_narf(&root)?;
        let mut linux_view = linux::restore(&pristine, id, &dir.join(format!("restore-pre-{id}")))?;
        drop_nested(&mut linux_view, &nested);
        expect_same(
            &format!("initial {name}: btrfs restore vs NARF"),
            &linux_view,
            &model.flatten(),
            FULL,
        )?;
        subs.push(Sub {
            name: name.to_string(),
            root,
            model,
            nested,
        });
    }
    let base_state: Vec<FlatTree> = subs.iter().map(|s| s.model.flatten()).collect();

    let mut wl = Workload::new(subs, &dev, seed);
    let mut p = sc.params.clone();
    p.ops = sc.ops;
    let ran = match sc.script {
        Some(script) => wl.run_script(script()),
        None => wl.run(&p),
    };
    std::fs::write(dir.join("trace.txt"), wl.trace.join("\n")).unwrap();
    if let Err(e) = ran {
        if args.verbose {
            eprintln!("--- trace:\n{}", wl.trace.join("\n"));
        }
        return Err(format!("workload: {e}"));
    }
    for s in &wl.subs {
        let (got, _) = narf::walk(&s.root)?;
        expect_same(
            &format!("{}: model vs NARF in-session read-back", s.name),
            &s.model.flatten(),
            &got,
            FULL,
        )?;
    }
    let final_state: Vec<FlatTree> = wl.subs.iter().map(|s| s.model.flatten()).collect();
    let nested: Vec<Vec<String>> = wl.subs.iter().map(|s| s.nested.clone()).collect();
    let stats = wl.stats.clone();
    let commits = std::mem::take(&mut wl.commits);
    drop(wl);
    drop(views);
    narf::reset();
    dev.set_recording(false);
    let log = dev.take_log();
    if !dev.violations().is_empty() {
        return Err(format!("request-shape violations: {:#?}", dev.violations()));
    }
    let (writes, flushes) = (dev.writes(), dev.flushes());
    drop(dev);

    // Linux's verdict on the final image.
    linux::check(&work, false)?;
    linux::check(&work, true)?;
    for (i, (name, id)) in [("@", at_id), ("@home", home_id)].into_iter().enumerate() {
        let mut got = linux::restore(&work, id, &dir.join(format!("restore-post-{id}")))?;
        drop_nested(&mut got, &nested[i]);
        expect_same(
            &format!("{name}: model vs btrfs restore"),
            &final_state[i],
            &got,
            FULL,
        )?;
    }
    let subvols_after = linux::subvolumes(&work)?;
    for (id, (name, pre)) in &pre_snaps {
        if !subvols_after.iter().any(|s| s.id == *id) {
            return Err(format!("snapshot {id} ({name}) disappeared"));
        }
        let post = linux::restore(&work, *id, &dir.join(format!("restore-post-{id}")))?;
        expect_same(
            &format!("snapshot {id} ({name}): restore before vs after"),
            pre,
            &post,
            FULL,
        )?;
    }
    let chunks_after = linux::chunk_counts(&work);

    // A fresh NARF boot of the final image sees the model, and reads every
    // snapshot exactly as Linux restores it.
    {
        let dev2 = Arc::new(RecDev::open(&work, sc.lba, fsid, nodesize));
        narf::register_root(dev2.clone(), &fsid)?;
        let views = narf::mount_root_rw(&fsid, "@", &["@home"])?;
        for (i, v) in views.iter().enumerate() {
            let (got, _) = narf::walk(&v.root())?;
            expect_same(
                &format!("subvol {i}: model vs NARF remount"),
                &final_state[i],
                &got,
                FULL,
            )?;
        }
        for (id, (name, pre)) in &pre_snaps {
            let fs = mount_subvolid(*id).map_err(|e| format!("subvolid={id} ({name}): {e:?}"))?;
            let (got, nested) = narf::walk(&fs.root())?;
            let mut want = pre.clone();
            drop_nested(&mut want, &nested);
            expect_same(
                &format!("snapshot {id} ({name}): restore vs NARF"),
                &want,
                &got,
                FULL,
            )?;
        }
        drop(views);
        narf::reset();
        if !dev2.violations().is_empty() {
            return Err(format!(
                "remount request-shape violations: {:?}",
                dev2.violations()
            ));
        }
    }
    linux::check(&work, false).map_err(|e| format!("after NARF remount: {e}"))?;

    let mut crash_line = String::from("crash pass off");
    if sc.cuts > 0 {
        let others = ["@home"];
        let inp = crash::Input {
            base: &pristine,
            log: &log,
            commits: &commits,
            base_gen,
            base_state,
            lba: sc.lba,
            fsid,
            nodesize,
            root_subvol: "@",
            others: &others,
        };
        let opts = crash::Opts {
            cuts: sc.cuts,
            exhaustive: args.exhaustive || sc.script.is_some(),
            seed,
            jobs: args.jobs,
            workdir: dir.join("crash"),
        };
        let rep = crash::run(&inp, &opts);
        if !rep.failures.is_empty() {
            return Err(format!(
                "crash consistency: {} of {} cut points failed (images kept in {}):\n{}",
                rep.failures.len(),
                rep.cuts,
                opts.workdir.display(),
                rep.failures.join("\n")
            ));
        }
        crash_line = format!(
            "crash: {} cuts over {} events / {} flushes, {} distinct generations, {} torn + {} dropped volatile writes",
            rep.cuts,
            log.len(),
            rep.flush_boundaries,
            rep.gens_seen.len(),
            rep.torn,
            rep.dropped
        );
    }
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    let ops: Vec<String> = stats.ops.iter().map(|(k, v)| format!("{k}:{v}")).collect();
    Ok(format!(
        "{} seed {seed}: OK in {:.1?}\n    @ {} | @home {}\n    {} commits, {:.1} MiB written by ops, device {writes} writes / {flushes} flushes; chunks data {}->{} metadata {}->{}; {} snapshots unchanged\n    ops {}\n    {crash_line}",
        sc.name,
        t0.elapsed(),
        summarize(&final_state[0]),
        summarize(&final_state[1]),
        stats.commits,
        stats.bytes_written as f64 / 1048576.0,
        chunks_before.0,
        chunks_after.0,
        chunks_before.1,
        chunks_after.1,
        pre_snaps.len(),
        ops.join(" "),
    ))
}

/// Fixtures `rw_gate` must refuse under root-rw, without a single device
/// write; and the accepted baseline beside them.
fn run_gate(args: &Args) -> Result<String, String> {
    let dir = args.workdir.join("gate");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let rootdir = dir.join("rootdir");
    std::fs::create_dir_all(rootdir.join("@/etc")).unwrap();
    std::fs::create_dir_all(rootdir.join("@home")).unwrap();
    std::fs::write(rootdir.join("@/etc/hostname"), b"gate\n").unwrap();
    let cases: [(&str, &str, &str); 4] = [
        (
            "accepted baseline",
            "crc32c",
            "block-group-tree,free-space-tree,no-holes",
        ),
        (
            "non-skinny metadata",
            "crc32c",
            "^skinny-metadata,free-space-tree,block-group-tree",
        ),
        (
            "xxhash checksums",
            "xxhash",
            "block-group-tree,free-space-tree",
        ),
        (
            "no free-space tree",
            "crc32c",
            "^free-space-tree,^block-group-tree",
        ),
    ];
    let mut lines = Vec::new();
    for (i, (what, csum, features)) in cases.iter().enumerate() {
        let img = dir.join(format!("gate{i}.img"));
        fixture::mkfs(
            &img,
            &rootdir,
            &fixture::MkfsSpec {
                uuid: &format!(
                    "c4c405ee-0000-4a11-9e57-{:012x}",
                    0x6a7e_0000_0000u64 + i as u64
                ),
                size: 256 << 20,
                nodesize: 16384,
                csum,
                features,
            },
        )?;
        let (fsid, nodesize, _) = dev::image_identity(&img);
        let dev = Arc::new(RecDev::open(&img, 512, fsid, nodesize));
        narf::register_root(dev.clone(), &fsid)?;
        let r = narf::mount_root_rw(&fsid, "@", &[]);
        let refusal = narf_drivers_fs_btrfs::rw_gate::last_refusal();
        let accepted = r.is_ok();
        drop(r);
        narf::reset();
        let writes = dev.writes();
        if i == 0 {
            if !accepted {
                return Err(format!("gate: {what} refused: {refusal:?}"));
            }
            lines.push(format!("    {what}: accepted read-write"));
        } else {
            if accepted {
                return Err(format!("gate: {what} was mounted read-write"));
            }
            if writes != 0 {
                return Err(format!(
                    "gate: {what}: {writes} device writes despite the refusal"
                ));
            }
            let why = refusal.unwrap_or_default();
            let why = why
                .split(": REFUSING read-write mount: ")
                .nth(1)
                .unwrap_or(&why);
            lines.push(format!(
                "    {what}: refused with 0 device writes ({})",
                why.split(';').next().unwrap_or("")
            ));
        }
    }
    if !args.keep {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(format!("gate: OK\n{}", lines.join("\n")))
}

// Minimal reproductions of the bugs this harness found, each first seen on
// a random seed (see the driver spec's testing section).
fn p(n: &str) -> String {
    format!("regress/{n}")
}

/// A write past EOF must zero the old last sector's tail even when a
/// compressed extent backs it (`mkfs --compress` frames end at i_size):
/// root seed 1, where `btrfs restore` read stale bytes in the gap.
fn regress_zstd_tail() -> Vec<Op> {
    vec![Op::WriteAt {
        sub: 0,
        path: p("zstd-tail"),
        off: 30413,
        len: 100,
    }]
}

/// fallocate inside an inline file's first sector preallocated an unaligned
/// extent beside the inline one (`btrfs check`: "file extent overlap"):
/// snapshots seed 1.
fn regress_inline_falloc() -> Vec<Op> {
    vec![Op::Fallocate {
        sub: 0,
        path: p("inline"),
        mode: 0,
        off: 1154,
        len: 541,
    }]
}

/// A truncate's tail zeroing and its size change must commit together: with
/// the batch one operation short of full, the zeroing filled it and the
/// commit landed in between, so a crash left the old size with zeroed bytes
/// (root seed 2, crash cut 2). Same for a write past EOF.
fn regress_atomic() -> Vec<Op> {
    let mut ops = vec![Op::Sync { sub: 0 }];
    for target in ["trunc", "extend"] {
        for _ in 0..7 {
            ops.push(Op::Chmod {
                sub: 0,
                path: p("pad"),
                perms: 0o600,
            });
        }
        ops.push(match target {
            "trunc" => Op::Truncate {
                sub: 0,
                path: p("trunc"),
                len: 13,
            },
            _ => Op::WriteAt {
                sub: 0,
                path: p("extend"),
                off: 9000,
                len: 10,
            },
        });
        ops.push(Op::Chmod {
            sub: 0,
            path: p("pad"),
            perms: 0o644,
        });
        ops.push(Op::Sync { sub: 0 });
    }
    ops
}

fn regress(name: &'static str, script: fn() -> Vec<Op>) -> Scenario {
    Scenario {
        name,
        lba: 512,
        ops: 0,
        cuts: 1,
        source: Source::Mkfs {
            populate: fixture::populate_regress,
            scale: 1,
            size: 256 << 20,
        },
        params: Params {
            ops: 0,
            data_budget: 0,
            large_file: 0,
            burst: 0,
        },
        script: Some(script),
    }
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    host::init();
    let t0 = Instant::now();
    let scenarios = [
        regress("regress-zstd-tail", regress_zstd_tail),
        regress("regress-inline-falloc", regress_inline_falloc),
        regress("regress-atomic", regress_atomic),
        Scenario {
            name: "root",
            lba: 512,
            ops: args.ops,
            cuts: args.cuts,
            source: Source::Mkfs {
                populate: fixture::populate_root,
                scale: 1,
                size: 1 << 30,
            },
            params: Params {
                ops: 0,
                data_budget: 160 << 20,
                large_file: 24 << 20,
                burst: 500,
            },
            script: None,
        },
        Scenario {
            name: "snapshots",
            lba: 512,
            ops: args.ops / 2,
            cuts: args.cuts / 2,
            source: Source::Sparse("fixture-snapshots.img.sparse"),
            params: Params {
                ops: 0,
                data_budget: 40 << 20,
                large_file: 8 << 20,
                burst: 300,
            },
            script: None,
        },
        Scenario {
            name: "lba4k",
            lba: 4096,
            ops: args.ops / 4,
            cuts: args.cuts / 3,
            source: Source::Mkfs {
                populate: fixture::populate_root,
                scale: 1,
                size: 768 << 20,
            },
            params: Params {
                ops: 0,
                data_budget: 60 << 20,
                large_file: 12 << 20,
                burst: 300,
            },
            script: None,
        },
    ];
    let mut failed = 0;
    for name in &args.scenarios {
        if name == "gate" {
            match run_gate(&args) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    failed += 1;
                    println!("gate: FAIL\n{e}");
                }
            }
            continue;
        }
        let picked: Vec<&Scenario> = scenarios
            .iter()
            .filter(|s| s.name == name || (name == "regress" && s.name.starts_with("regress-")))
            .collect();
        for (sc, seed) in picked.iter().flat_map(|sc| {
            let n = if sc.script.is_some() { 1 } else { args.seeds };
            (args.seed..args.seed + n).map(move |seed| (*sc, seed))
        }) {
            match run_scenario(sc, seed, &args) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    failed += 1;
                    println!(
                        "{} seed {seed}: FAIL\n{e}\n(reproduce: narf-btrfs-host --scenario {} --seed {seed} --ops {} --cuts {} --keep -v)",
                        sc.name, sc.name, args.ops, args.cuts
                    );
                    narf::reset();
                }
            }
        }
    }
    println!(
        "btrfs-host-rw: {} in {:.1?}",
        if failed == 0 { "PASS" } else { "FAIL" },
        t0.elapsed()
    );
    std::process::exit(if failed == 0 { 0 } else { 1 });
}
