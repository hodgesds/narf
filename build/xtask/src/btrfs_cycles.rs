//! `cargo xtask btrfs-cycles`: many btrfs mount → write → sync → unmount →
//! remount → verify cycles in ONE boot per guest, on a CachyOS-shaped root.
//!
//! 1. The host builds, unprivileged, a btrfs image shaped like the CachyOS
//!    root (`mkfs.btrfs` 16 KiB nodes, crc32c, block-group tree + free-space
//!    tree, `--compress zstd:1`, `@` as the default subvolume and `@home`,
//!    seed files from `--rootdir`: inline files, a multi-MiB file, a
//!    compressible file, a symlink).
//! 2. Every job gets its own reflink/sparse copy and boots NARF directly
//!    (`-kernel`, no firmware, `-smp 1`, 1 GiB) with the image on NVMe with
//!    512-byte LBAs under `narf.disks=root-rw root=UUID=…`, so the policy
//!    designates it and the `rw_gate` root-rw profile applies. The guest
//!    half (`drivers/fs/btrfs/src/cycles.rs`) detaches `/` and runs the
//!    cycles, each one verifying every file of every earlier cycle against
//!    a model, and prints a final manifest.
//! 3. After the guest stops, the host runs `btrfs check --readonly
//!    --check-data-csum` and `btrfs restore` of `@` and `@home` on every
//!    image and compares the restored trees with the manifest and the seeds.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

/// fsid of the cycles fixture (carries the harness marker prefix).
pub const IMAGE_UUID: &str = "c4c405ee-0000-4a11-9e57-00000c7c1e50";
const IMAGE_MIB: u64 = 384;
const MARKER: &str = "BTRFS-CYCLES:";
/// Must equal `cycles::WORK_DIR`.
const WORK_DIR: &str = "narf-cycles";
/// Guest RAM per job, MiB.
const GUEST_MIB: u64 = 1024;
/// Host memory per job on top of guest RAM (QEMU itself), MiB.
const JOB_OVERHEAD_MIB: u64 = 256;
/// Host memory kept free whatever the job count, MiB.
const HOST_MARGIN_MIB: u64 = 2048;
/// Upper bound on `--jobs`.
pub const MAX_JOBS: usize = 30;

/// Options for `cargo xtask btrfs-cycles`.
#[derive(clap::Args, Clone)]
pub struct Args {
    #[command(flatten)]
    pub build: super::BuildArgs,

    /// Mount/write/unmount/verify cycles per guest.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=10_000))]
    pub cycles: u32,

    /// Base workload seed; job `i` uses `seed + i`.
    #[arg(long, default_value_t = 1)]
    pub seed: u64,

    /// Concurrent guests (default: min(nproc - 2, 10)), at most 30.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=MAX_JOBS as i64))]
    pub jobs: Option<u32>,

    /// Workload operations per cycle.
    #[arg(long, default_value_t = 80)]
    pub ops: u32,

    /// Live-data budget of the workload, KiB (beyond it, it shrinks files).
    #[arg(long, default_value_t = 32 * 1024)]
    pub live_kib: u64,

    /// Largest file one create writes, KiB.
    #[arg(long, default_value_t = 8 * 1024)]
    pub big_kib: u64,

    /// Seconds each guest may take, boot included.
    #[arg(long, default_value_t = 600)]
    pub timeout_secs: u64,

    /// Keep every job's disk image (by default only failed jobs' are kept).
    #[arg(long)]
    pub keep_images: bool,

    /// Boot this kernel instead of building one.
    #[arg(long, value_name = "PATH")]
    pub kernel: Option<PathBuf>,
}

/// `min(nproc - 2, 10)`, at least 1.
pub fn default_jobs(nproc: usize) -> usize {
    nproc.saturating_sub(2).clamp(1, 10)
}

/// Refuse a job count whose guests would not fit in `mem_available_kib`.
pub fn check_memory(jobs: usize, mem_available_kib: u64) -> Result<()> {
    let need_mib = jobs as u64 * (GUEST_MIB + JOB_OVERHEAD_MIB) + HOST_MARGIN_MIB;
    let have_mib = mem_available_kib / 1024;
    if need_mib > have_mib {
        bail!(
            "btrfs-cycles: {jobs} jobs need {need_mib} MiB ({GUEST_MIB} MiB guest + \
             {JOB_OVERHEAD_MIB} MiB QEMU each, {HOST_MARGIN_MIB} MiB margin) but only \
             {have_mib} MiB is available; lower --jobs"
        );
    }
    Ok(())
}

fn mem_available_kib() -> Result<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    text.lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .context("no MemAvailable in /proc/meminfo")
}

/// Must equal `cycles::compressible`.
pub fn compressible(seed: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut n = 0u32;
    while out.len() < len {
        out.extend_from_slice(
            format!("narf btrfs cycles seed {seed:04} line {n:08} the quick brown fox\n")
                .as_bytes(),
        );
        n += 1;
    }
    out.truncate(len);
    out
}

/// Must equal `cycles::fnv64`.
pub fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

enum Seed {
    File(Vec<u8>),
    Symlink(&'static str),
}

/// Must equal `cycles::seed_files`.
fn seed_files() -> Vec<(&'static str, &'static str, Seed)> {
    use super::btrfs_interop::pattern;
    vec![
        ("@", "etc/hostname", Seed::File(b"cachyos\n".to_vec())),
        (
            "@",
            "etc/os-release",
            Seed::File(b"NAME=\"CachyOS Linux\"\nID=cachyos\nBUILD_ID=rolling\n".to_vec()),
        ),
        (
            "@",
            "usr/share/cycles/inline.txt",
            Seed::File(compressible(1, 300)),
        ),
        (
            "@",
            "usr/share/cycles/compressible.txt",
            Seed::File(compressible(2, 1 << 20)),
        ),
        (
            "@",
            "usr/share/cycles/random.bin",
            Seed::File(pattern(77, 3 << 20)),
        ),
        (
            "@",
            "usr/share/cycles/random.link",
            Seed::Symlink("random.bin"),
        ),
        (
            "@home",
            "narf/.bashrc",
            Seed::File(b"export EDITOR=vi\nalias ll='ls -l'\n".to_vec()),
        ),
        ("@home", "narf/notes.bin", Seed::File(pattern(78, 200_000))),
    ]
}

fn run_tool(cmd: &mut Command, what: &str) -> Result<String> {
    let out = cmd.output().with_context(|| format!("running {what}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        bail!("btrfs-cycles: {what} failed ({}):\n{text}", out.status);
    }
    Ok(text)
}

/// First LBA (512-byte sectors) of the root partition.
const PART_START_LBA: u64 = 2048;

/// Build the fixture at `out`: a GPT disk with one Linux partition holding
/// the btrfs root (the root policy designates a partition, never a whole
/// disk). The stage tree and the raw filesystem live under `work`.
fn build_fixture(work: &Path, out: &Path) -> Result<()> {
    let stage = work.join("stage");
    let _ = std::fs::remove_dir_all(&stage);
    for (sv, path, seed) in seed_files() {
        let at = stage.join(sv).join(path);
        std::fs::create_dir_all(at.parent().context("seed parent")?)?;
        match seed {
            Seed::File(data) => std::fs::write(&at, data)?,
            Seed::Symlink(target) => std::os::unix::fs::symlink(target, &at)?,
        }
    }
    let fs = work.join("root.btrfs");
    let _ = std::fs::remove_file(&fs);
    std::fs::File::create(&fs)?.set_len(IMAGE_MIB << 20)?;
    run_tool(
        Command::new("mkfs.btrfs")
            .args(["-q", "-f", "-U", IMAGE_UUID, "-L", "cachyos"])
            .args(["-n", "16384", "-s", "4096", "--csum", "crc32c"])
            .args([
                "-O",
                "block-group-tree,free-space-tree",
                "--compress",
                "zstd:1",
            ])
            .arg("--rootdir")
            .arg(&stage)
            .args(["--subvol", "default:@", "--subvol", "rw:@home"])
            .arg(&fs),
        "mkfs.btrfs",
    )?;
    let sectors = IMAGE_MIB * 2048;
    let _ = std::fs::remove_file(out);
    std::fs::File::create(out)?.set_len((PART_START_LBA + sectors + 2048) * 512)?;
    let table = format!(
        "label: gpt\nstart={PART_START_LBA}, size={sectors}, \
         type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=\"root\"\n"
    );
    let mut sfdisk = Command::new("sfdisk")
        .arg("-q")
        .arg(out)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("spawn sfdisk")?;
    sfdisk
        .stdin
        .as_mut()
        .context("sfdisk stdin")?
        .write_all(table.as_bytes())?;
    if !sfdisk.wait()?.success() {
        bail!("btrfs-cycles: sfdisk failed");
    }
    run_tool(
        Command::new("dd")
            .arg(format!("if={}", fs.display()))
            .arg(format!("of={}", out.display()))
            .args([
                "bs=1M",
                &format!("seek={}", PART_START_LBA / 2048),
                "conv=notrunc,sparse",
                "status=none",
            ]),
        "dd (root partition)",
    )?;
    let _ = std::fs::remove_file(&fs);
    Ok(())
}

/// Copy the root partition of the disk image `disk` to `out` (sparse).
fn extract_partition(disk: &Path, out: &Path) -> Result<()> {
    run_tool(
        Command::new("dd")
            .arg(format!("if={}", disk.display()))
            .arg(format!("of={}", out.display()))
            .args([
                "bs=1M",
                &format!("skip={}", PART_START_LBA / 2048),
                &format!("count={IMAGE_MIB}"),
                "conv=sparse",
                "status=none",
            ]),
        "dd (extract root partition)",
    )?;
    Ok(())
}

/// What one guest reported.
#[derive(Default, Debug)]
struct JobState {
    cycles_ok: u32,
    started_at: Option<f64>,
    detached_at: Option<f64>,
    pass: Option<String>,
    fail: Option<String>,
    panic: Option<String>,
    last_cycle_line: Option<String>,
    manifest_files: BTreeMap<(String, String), (u64, u64)>,
    manifest_dirs: BTreeSet<(String, String)>,
}

/// Parse one serial line into `state`.
fn note_line(state: &mut JobState, line: &str, at: f64) {
    if super::PANIC_MARKERS.iter().any(|m| line.contains(m)) && state.panic.is_none() {
        state.panic = Some(line.to_string());
    }
    if (line.contains("ROOTRW-INTEROP: NO-ROOT")
        || line.contains("ROOTRW-INTEROP: REFUSED")
        || line.contains("ROOT MOUNT FAILED"))
        && state.fail.is_none()
    {
        state.fail = Some(line.trim().to_string());
    }
    let Some((_, rest)) = line.split_once(MARKER) else {
        return;
    };
    let rest = rest.trim();
    let mut words = rest.split_whitespace();
    match words.next() {
        Some("START") => state.started_at = Some(at),
        Some("BOOT-ROOT-DETACHED") => state.detached_at = Some(at),
        Some("CYCLE") => {
            state.cycles_ok += 1;
            state.last_cycle_line = Some(rest.to_string());
        }
        Some("FILE") => {
            let w: Vec<&str> = words.collect();
            if let [sv, path, len, hash] = w[..] {
                if let (Ok(len), Ok(hash)) = (len.parse(), u64::from_str_radix(hash, 16)) {
                    state
                        .manifest_files
                        .insert((sv.to_string(), path.to_string()), (len, hash));
                }
            }
        }
        Some("DIR") => {
            let w: Vec<&str> = words.collect();
            if let [sv, path] = w[..] {
                state
                    .manifest_dirs
                    .insert((sv.to_string(), path.to_string()));
            }
        }
        Some("PASS") => state.pass = Some(rest.to_string()),
        Some("FAIL") => {
            state.fail = Some(rest.strip_prefix("FAIL").unwrap_or(rest).trim().to_string())
        }
        _ => {}
    }
}

/// The QEMU command line of one job: direct kernel boot, no firmware, one
/// vCPU, only the NVMe disk.
fn qemu_args(kernel: &Path, image: &Path, append: &str, kvm: bool) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-machine".into(),
        "q35".into(),
        "-cpu".into(),
        "max,phys-bits=40".into(),
        "-smp".into(),
        "1".into(),
        "-m".into(),
        format!("{GUEST_MIB}M"),
    ];
    if kvm {
        args.extend(["-accel".into(), "kvm".into()]);
    }
    args.extend([
        // No default CD-ROM, NIC, VGA or monitor: only what is listed.
        "-nodefaults".into(),
        "-serial".into(),
        "stdio".into(),
        "-display".into(),
        "none".into(),
        "-no-reboot".into(),
        "-device".into(),
        "isa-debug-exit,iobase=0xf4,iosize=0x04".into(),
        "-drive".into(),
        format!("if=none,id=nvm0,format=raw,file={}", image.display()),
        "-device".into(),
        "nvme,drive=nvm0,serial=narfcycles,logical_block_size=512,physical_block_size=512".into(),
        "-append".into(),
        append.into(),
        "-kernel".into(),
        kernel.display().to_string(),
    ]);
    args
}

fn guest_cmdline(args: &Args, seed: u64) -> String {
    format!(
        "narf.disks=root-rw root=UUID={IMAGE_UUID} rootflags=subvol=/@ \
         narf.rootrw_interop=cycles narf.btrfs_cycles={} narf.btrfs_cycles_seed={seed} \
         narf.btrfs_cycles_ops={} narf.btrfs_cycles_live_kib={} narf.btrfs_cycles_big_kib={}",
        args.cycles, args.ops, args.live_kib, args.big_kib
    )
}

struct Job {
    index: usize,
    seed: u64,
    image: PathBuf,
    log: PathBuf,
    state: Arc<Mutex<JobState>>,
    /// Seconds from spawn to the guest's verdict (or stop).
    guest_secs: f64,
}

/// Boot every job concurrently and wait for all verdicts.
fn run_guests(args: &Args, kernel: &Path, jobs: &mut [Job]) -> Result<()> {
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    let mut children = Vec::new();
    let started = Instant::now();
    for job in jobs.iter() {
        let append = guest_cmdline(args, job.seed);
        let mut child = Command::new(args.build.arch.qemu_bin())
            .args(qemu_args(kernel, &job.image, &append, kvm))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn qemu")?;
        let stdout = child.stdout.take().context("qemu stdout")?;
        let stderr = child.stderr.take().context("qemu stderr")?;
        let state = job.state.clone();
        let mut log = std::fs::File::create(&job.log)?;
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let at = started.elapsed().as_secs_f64();
                let _ = writeln!(log, "[{at:8.3}] {line}");
                if let Ok(mut s) = state.lock() {
                    note_line(&mut s, &line, at);
                }
            }
            let mut rest = String::new();
            let _ = std::io::Read::read_to_string(&mut BufReader::new(stderr), &mut rest);
            if !rest.is_empty() {
                let _ = writeln!(log, "[qemu stderr] {rest}");
            }
        });
        children.push((child, Some(reader), false));
    }
    let deadline = started + Duration::from_secs(args.timeout_secs);
    let mut last_report = Instant::now();
    loop {
        let mut running = 0;
        for (i, (child, reader, done)) in children.iter_mut().enumerate() {
            if *done {
                continue;
            }
            let verdict = {
                let s = jobs[i].state.lock().expect("job state");
                s.pass.is_some() || s.fail.is_some() || s.panic.is_some()
            };
            let exited = matches!(child.try_wait(), Ok(Some(_)));
            if verdict || exited || Instant::now() >= deadline {
                if verdict {
                    // The verdict follows the final unmount; let the last
                    // lines drain, then stop the guest.
                    std::thread::sleep(Duration::from_millis(100));
                }
                let _ = child.kill();
                let _ = child.wait();
                if let Some(r) = reader.take() {
                    let _ = r.join();
                }
                jobs[i].guest_secs = started.elapsed().as_secs_f64();
                *done = true;
                let s = jobs[i].state.lock().expect("job state");
                if s.fail.is_some() || s.panic.is_some() {
                    println!(
                        "btrfs-cycles: job {i} (seed {}) FAILED after {} cycles: {}",
                        jobs[i].seed,
                        s.cycles_ok,
                        s.fail.as_deref().or(s.panic.as_deref()).unwrap_or("")
                    );
                }
            } else {
                running += 1;
            }
        }
        if running == 0 {
            break;
        }
        if last_report.elapsed() >= Duration::from_secs(15) {
            last_report = Instant::now();
            let progress: Vec<String> = jobs
                .iter()
                .map(|j| format!("{}", j.state.lock().map(|s| s.cycles_ok).unwrap_or(0)))
                .collect();
            println!(
                "btrfs-cycles: {:5.1}s cycles done per job: [{}]",
                started.elapsed().as_secs_f64(),
                progress.join(" ")
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Walk `dir` (relative paths under `base`), collecting files and dirs.
fn walk(
    base: &Path,
    dir: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
    dirs: &mut BTreeSet<String>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(base)?.to_string_lossy().into_owned();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            dirs.insert(rel);
            walk(base, &path, files, dirs)?;
        } else if kind.is_file() {
            files.insert(rel, std::fs::read(&path)?);
        } else {
            bail!("unexpected non-file entry {rel} after restore");
        }
    }
    Ok(())
}

/// Root level of the tree `dump-tree -t <tree>` prints first.
fn tree_level(image: &Path, tree: &str) -> Result<u32> {
    let text = run_tool(
        Command::new("btrfs")
            .args(["inspect-internal", "dump-tree", "-t", tree])
            .arg(image),
        "btrfs dump-tree",
    )?;
    text.lines()
        .find_map(|l| {
            let l = l.trim_start();
            // `leaf <bytenr> items ...` (a level-0 root carries no level),
            // `node <bytenr> level <n> items ...`.
            if l.starts_with("leaf ") {
                return Some(0);
            }
            let level = l.strip_prefix("node ")?.split_once(" level ")?.1;
            level.split_whitespace().next()?.parse().ok()
        })
        .context("no root node in dump-tree output")
}

/// Chunk count and tree heights: evidence the run grew the filesystem and
/// split its trees (the fixture starts with 3 chunks and single leaves).
fn tree_shape(image: &Path, ids: &[(u64, String)]) -> Result<String> {
    let chunks = run_tool(
        Command::new("btrfs")
            .args(["inspect-internal", "dump-tree", "-t", "chunk"])
            .arg(image),
        "btrfs dump-tree -t chunk",
    )?
    .matches("CHUNK_ITEM")
    .count();
    let at = ids
        .iter()
        .find(|(_, n)| n == "@")
        .map(|(id, _)| id.to_string())
        .context("no @")?;
    Ok(format!(
        "{chunks} chunks, @ tree level {}, extent tree level {}",
        tree_level(image, &at)?,
        tree_level(image, "extent")?
    ))
}

/// Host checks of one job's image.
fn check_image(job: &Job, work: &Path) -> Result<String> {
    std::fs::create_dir_all(work)?;
    let image = &work.join("root.btrfs");
    extract_partition(&job.image, image)?;
    let text = run_tool(
        Command::new("btrfs")
            .args(["check", "--readonly", "--check-data-csum"])
            .arg(image),
        "btrfs check",
    )?;
    if text.contains("ERROR") || text.contains("error(s) found") || !text.contains("no error found")
    {
        bail!("btrfs check found errors:\n{text}");
    }
    let ids = super::btrfs_interop::subvol_ids(image)?;
    let state = job.state.lock().expect("job state");
    let mut restored_files = 0usize;
    for sv in ["@", "@home"] {
        let id = ids
            .iter()
            .find(|(_, n)| n == sv)
            .map(|(id, _)| *id)
            .with_context(|| format!("subvolume {sv} missing from the root tree"))?;
        let dest = work.join(format!("restore-{}", sv.trim_start_matches('@')));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest)?;
        run_tool(
            Command::new("btrfs")
                .args(["restore", "-S", "-r", &id.to_string()])
                .arg(image)
                .arg(&dest),
            "btrfs restore",
        )?;
        for (seed_sv, path, seed) in seed_files() {
            if seed_sv != sv {
                continue;
            }
            let at = dest.join(path);
            match seed {
                Seed::File(want) => {
                    let got = std::fs::read(&at)
                        .with_context(|| format!("seed {sv}/{path} missing after restore"))?;
                    if got != want {
                        bail!("seed {sv}/{path} differs after restore");
                    }
                }
                Seed::Symlink(target) => {
                    let got = std::fs::read_link(&at)
                        .with_context(|| format!("seed symlink {sv}/{path} missing"))?;
                    if got != Path::new(target) {
                        bail!("seed symlink {sv}/{path} -> {}", got.display());
                    }
                }
            }
        }
        let mut files = BTreeMap::new();
        let mut dirs = BTreeSet::new();
        let top = dest.join(WORK_DIR);
        dirs.insert(WORK_DIR.to_string());
        walk(&dest, &top, &mut files, &mut dirs)?;
        let want_dirs: BTreeSet<String> = state
            .manifest_dirs
            .iter()
            .filter(|(s, _)| s == sv)
            .map(|(_, p)| p.clone())
            .collect();
        if dirs != want_dirs {
            bail!(
                "{sv}: restored directories differ from the guest manifest: extra {:?} missing {:?}",
                dirs.difference(&want_dirs).collect::<Vec<_>>(),
                want_dirs.difference(&dirs).collect::<Vec<_>>()
            );
        }
        let want_files: BTreeMap<&String, &(u64, u64)> = state
            .manifest_files
            .iter()
            .filter(|((s, _), _)| s == sv)
            .map(|((_, p), v)| (p, v))
            .collect();
        for (path, &&(len, hash)) in &want_files {
            let got = files
                .get(*path)
                .with_context(|| format!("{sv}/{path} missing after restore"))?;
            if got.len() as u64 != len || fnv64(got) != hash {
                bail!(
                    "{sv}/{path} differs after restore: {} bytes fnv {:016x}, guest model {len} bytes fnv {hash:016x}",
                    got.len(),
                    fnv64(got)
                );
            }
        }
        if let Some(extra) = files.keys().find(|p| !want_files.contains_key(p)) {
            bail!("{sv}/{extra} restored but not in the guest manifest");
        }
        restored_files += files.len();
        let _ = std::fs::remove_dir_all(&dest);
    }
    let shape = tree_shape(image, &ids).unwrap_or_else(|e| format!("shape unknown: {e:#}"));
    Ok(format!(
        "check clean, restore matched {restored_files} files; {shape}"
    ))
}

pub fn run(args: &Args) -> Result<()> {
    let wall = Instant::now();
    if !matches!(args.build.arch, super::Arch::X86_64) {
        bail!("btrfs-cycles: x86_64 only");
    }
    for tool in [
        "mkfs.btrfs",
        "btrfs",
        "sfdisk",
        "dd",
        "cp",
        args.build.arch.qemu_bin(),
    ] {
        if super::which(tool).is_none() {
            bail!("btrfs-cycles: `{tool}` not on $PATH");
        }
    }
    let nproc = std::thread::available_parallelism().map_or(4, |n| n.get());
    let njobs = args
        .jobs
        .map_or_else(|| default_jobs(nproc), |j| j as usize);
    check_memory(njobs, mem_available_kib()?)?;
    let root = super::workspace_root()?;

    let t = Instant::now();
    let kernel = match &args.kernel {
        Some(k) => k.clone(),
        None => super::cargo_build(&args.build, &root)?.join(&args.build.package),
    };
    if !kernel.exists() {
        bail!("btrfs-cycles: no kernel at {}", kernel.display());
    }
    let build_secs = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let run_dir = root
        .join("target/btrfs-cycles")
        .join(format!("run-{stamp}"));
    std::fs::create_dir_all(&run_dir)?;
    let base = run_dir.join("fixture.img");
    build_fixture(&run_dir, &base)?;
    let mut jobs = Vec::new();
    for index in 0..njobs {
        let image = run_dir.join(format!("job{index:02}.img"));
        run_tool(
            Command::new("cp")
                .args(["--reflink=auto", "--sparse=always"])
                .arg(&base)
                .arg(&image),
            "cp fixture",
        )?;
        jobs.push(Job {
            index,
            seed: args.seed + index as u64,
            image,
            log: run_dir.join(format!("job{index:02}.serial.log")),
            state: Arc::new(Mutex::new(JobState::default())),
            guest_secs: 0.0,
        });
    }
    let fixture_secs = t.elapsed().as_secs_f64();
    println!(
        "btrfs-cycles: {njobs} job(s) x {} cycles, seeds {}..={}, logs in {}",
        args.cycles,
        args.seed,
        args.seed + njobs as u64 - 1,
        run_dir.display()
    );

    let t = Instant::now();
    run_guests(args, &kernel, &mut jobs)?;
    let guest_secs = t.elapsed().as_secs_f64();

    // Host checks, in parallel, of every image whose guest passed.
    let t = Instant::now();
    let checks: Vec<Result<String>> = std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .iter()
            .map(|job| {
                let work = run_dir.join(format!("job{:02}-restore", job.index));
                scope.spawn(move || -> Result<String> {
                    let passed = job.state.lock().map(|s| s.pass.is_some()).unwrap_or(false);
                    if !passed {
                        bail!("guest did not pass");
                    }
                    let r = check_image(job, &work);
                    let _ = std::fs::remove_dir_all(&work);
                    r
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("check panicked")))
            })
            .collect()
    });
    let check_secs = t.elapsed().as_secs_f64();

    println!();
    println!("job  seed        cycles  boot_s  guest_s  result");
    let mut failed = Vec::new();
    for (job, check) in jobs.iter().zip(&checks) {
        let s = job.state.lock().expect("job state");
        let boot = s.started_at.map_or("-".into(), |b| format!("{b:.1}"));
        let result = match (&s.fail, &s.panic, &s.pass, check) {
            (Some(f), _, _, _) => format!("FAIL {f}"),
            (None, Some(p), _, _) => format!("PANIC {p}"),
            (None, None, None, _) => format!(
                "NO VERDICT (timeout or guest exit; last: {})",
                s.last_cycle_line.as_deref().unwrap_or("none")
            ),
            (_, _, Some(_), Err(e)) => format!("HOST CHECK FAILED: {e:#}"),
            (_, _, Some(_), Ok(ok)) => format!("ok: {ok}"),
        };
        println!(
            "{:>3}  {:<10}  {:>6}  {:>6}  {:>7.1}  {}",
            job.index,
            job.seed,
            s.cycles_ok,
            boot,
            job.guest_secs,
            result.lines().next().unwrap_or("")
        );
        if !(s.pass.is_some() && check.is_ok()) {
            failed.push((job.index, job.seed, s.cycles_ok + 1, result));
        }
    }
    println!();
    println!(
        "btrfs-cycles: phases: build {build_secs:.1}s, fixture {fixture_secs:.1}s, guests {guest_secs:.1}s, host checks {check_secs:.1}s; total wall {:.1}s",
        wall.elapsed().as_secs_f64()
    );
    if !failed.is_empty() {
        for (index, seed, cycle, why) in &failed {
            eprintln!("btrfs-cycles: job {index} seed {seed} failed at cycle {cycle}:\n{why}");
            eprintln!(
                "  serial log: {}",
                run_dir.join(format!("job{index:02}.serial.log")).display()
            );
        }
        bail!("btrfs-cycles: {} of {njobs} job(s) failed", failed.len());
    }
    // Images of a passing run are not needed again.
    if !args.keep_images {
        for job in &jobs {
            let _ = std::fs::remove_file(&job.image);
        }
    }
    let _ = std::fs::remove_dir_all(run_dir.join("stage"));
    println!(
        "btrfs-cycles: OK — {njobs} job(s) x {} cycles, every image check-clean and restore-identical",
        args.cycles
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: Args,
    }

    fn parse(argv: &[&str]) -> Result<Args, clap::Error> {
        Cli::try_parse_from(std::iter::once("btrfs-cycles").chain(argv.iter().copied()))
            .map(|c| c.args)
    }

    #[test]
    fn defaults() {
        let a = parse(&[]).unwrap();
        assert_eq!(a.cycles, 50);
        assert_eq!(a.seed, 1);
        assert_eq!(a.jobs, None);
        assert!(a.kernel.is_none());
    }

    #[test]
    fn explicit_values_and_bounds() {
        let a = parse(&[
            "--cycles", "7", "--seed", "42", "--jobs", "3", "--ops", "10",
        ])
        .unwrap();
        assert_eq!((a.cycles, a.seed, a.jobs, a.ops), (7, 42, Some(3), 10));
        assert!(parse(&["--jobs", "0"]).is_err());
        assert!(parse(&["--jobs", "31"]).is_err());
        assert!(parse(&["--jobs", "30"]).is_ok());
        assert!(parse(&["--cycles", "0"]).is_err());
    }

    #[test]
    fn default_job_count() {
        assert_eq!(default_jobs(12), 10);
        assert_eq!(default_jobs(8), 6);
        assert_eq!(default_jobs(2), 1);
        assert_eq!(default_jobs(1), 1);
        assert_eq!(default_jobs(64), 10);
    }

    #[test]
    fn memory_gate() {
        // 10 jobs need 10 * 1280 + 2048 MiB.
        assert!(check_memory(10, (10 * 1280 + 2048) * 1024).is_ok());
        assert!(check_memory(10, (10 * 1280 + 2047) * 1024).is_err());
        assert!(check_memory(30, 32 * 1024 * 1024).is_err());
        assert!(check_memory(30, 61 * 1024 * 1024).is_ok());
    }

    #[test]
    fn serial_parsing() {
        let mut s = JobState::default();
        for line in [
            "BTRFS-CYCLES: START cycles=2 seed=1",
            "BTRFS-CYCLES: CYCLE 1/2 ok gen=12",
            "BTRFS-CYCLES: CYCLE 2/2 ok gen=15",
            "BTRFS-CYCLES: DIR @ narf-cycles",
            "BTRFS-CYCLES: FILE @home narf-cycles/d3/f9 4096 00000000deadbeef",
            "BTRFS-CYCLES: PASS cycles=2",
        ] {
            note_line(&mut s, line, 1.0);
        }
        assert_eq!(s.cycles_ok, 2);
        assert!(s.pass.is_some() && s.fail.is_none() && s.panic.is_none());
        assert!(s
            .manifest_dirs
            .contains(&("@".into(), "narf-cycles".into())));
        assert_eq!(
            s.manifest_files[&("@home".into(), "narf-cycles/d3/f9".into())],
            (4096, 0xdead_beef)
        );
        note_line(&mut s, "panicked at drivers/fs/btrfs/src/write.rs:1:1", 2.0);
        assert!(s.panic.is_some());
    }

    #[test]
    fn digests_match_the_guest() {
        assert_eq!(fnv64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv64(b"a"), 0xaf63_dc4c_8601_ec8c);
        let c = compressible(2, 100);
        assert_eq!(c.len(), 100);
        assert!(c.starts_with(b"narf btrfs cycles seed 0002 line 00000000 "));
    }
}
