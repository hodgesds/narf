//! `cargo xtask btrfs-crash-smoke`: btrfs commit durability across an abrupt
//! stop.
//!
//! Boot 1 (`narf.btrfs_crash=write`) writes and `fsync`s a patterned file on
//! a disposable btrfs NVMe image, prints `NARF-BTRFS-CRASH: COMMITTED`, and
//! keeps writing uncommitted noise. The host SIGKILLs QEMU the moment that
//! line arrives, so the stop lands mid-transaction with I/O in flight. Boot
//! 2 (`narf.btrfs_crash=verify`) mounts the same image read-only and must
//! find the fsynced file intact. Then host `btrfs check --readonly` must pass.
//! The guest half is `drivers/fs/btrfs/src/crash_check.rs`.
//!
//! The kill happens at the QEMU process, so data that QEMU had handed to the
//! host page cache survives. What the test proves is that everything `fsync`
//! promised had left the guest (its trees, the pre-flush, and the FUA
//! superblock) when `fsync` returned, and that the uncommitted transaction
//! open at kill time leaves a consistent image behind.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const COMMITTED: &str = "NARF-BTRFS-CRASH: COMMITTED";
const OK: &str = "NARF-BTRFS-CRASH: OK";
const FAIL: &str = "NARF-BTRFS-CRASH: FAIL";

/// Options for the btrfs crash smoke.
#[derive(clap::Args, Clone)]
pub struct Args {
    #[command(flatten)]
    pub build: super::BuildArgs,

    /// Use the BLOCK_GROUP_TREE (CachyOS feature set) fixture instead of the
    /// mixed free-space-bitmap one.
    #[arg(long)]
    pub bgt: bool,

    /// Use the tall fixture (4 KiB nodes, `@` fs tree three levels deep)
    /// and work inside `@`: the large-tree variant, where node splits under
    /// internal roots and the commit's multi-leaf fixed point are exercised.
    #[arg(long, conflicts_with = "bgt")]
    pub tall: bool,

    /// Seconds each boot may take to reach its marker.
    #[arg(long, default_value_t = 300)]
    pub timeout_secs: u64,
}

/// Boot the kernel once with `append` and return when a line containing one
/// of `markers` arrives (QEMU is SIGKILLed at that moment) or on timeout.
fn boot_until(
    build: &super::BuildArgs,
    kernel: &Path,
    append: &str,
    markers: &[&str],
    timeout: Duration,
) -> Result<Option<String>> {
    std::env::set_var("XTASK_QEMU_APPEND", append);
    let qemu = build.arch.qemu_bin();
    let mut child = Command::new(qemu)
        .args(super::qemu_boot_args(build, kernel)?)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {qemu}"))?;
    let stdout = child.stdout.take().context("qemu stdout")?;
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            println!("{line}");
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + timeout;
    let mut hit = None;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if let Some(m) = markers.iter().find(|m| line.contains(*m)) {
                    // Kill first: the point is to stop the guest mid-flight.
                    let _ = child.kill();
                    hit = Some((*m).to_string());
                    break;
                }
                if line.contains("*** KERNEL PANIC ***") || line.contains("panicked at") {
                    let _ = child.kill();
                    bail!("btrfs-crash-smoke: kernel panic: {line}");
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    drop(rx);
    let _ = reader.join();
    Ok(hit)
}

pub fn run(args: &Args) -> Result<()> {
    if !matches!(args.build.arch, super::Arch::X86_64) {
        bail!("btrfs-crash-smoke: x86_64 only");
    }
    let root = super::workspace_root()?;
    let image: PathBuf = root.join("target").join("narf-btrfs-crash.img");
    let fixture = if args.tall {
        "drivers/fs/btrfs/testdata/fixture-tall.img.sparse"
    } else if args.bgt {
        "drivers/fs/btrfs/testdata/fixture-bgt.img.sparse"
    } else {
        "drivers/fs/btrfs/testdata/fixture-bitmap.img.sparse"
    };
    super::reconstruct_sparse_fixture(fixture, &image);
    if !image.exists() {
        bail!("btrfs-crash-smoke: could not build {}", image.display());
    }
    std::env::set_var("NARF_NVME_IMG", &image);
    let prior_append = std::env::var("XTASK_QEMU_APPEND").unwrap_or_default();
    let subvol = if args.tall {
        "narf.btrfs_crash_subvol=@"
    } else {
        ""
    };
    let with = |flag: &str| {
        [prior_append.as_str(), subvol, flag]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" ")
    };

    let out_dir = super::cargo_build(&args.build, &root)?;
    let kernel = out_dir.join(&args.build.package);
    let timeout = Duration::from_secs(args.timeout_secs);

    println!("xtask btrfs-crash-smoke: boot 1 (write + fsync, then SIGKILL)");
    match boot_until(
        &args.build,
        &kernel,
        &with("narf.btrfs_crash=write"),
        &[COMMITTED, FAIL],
        timeout,
    )?
    .as_deref()
    {
        Some(COMMITTED) => {}
        Some(other) => bail!("btrfs-crash-smoke: write boot reported {other}"),
        None => bail!("btrfs-crash-smoke: write boot never reported {COMMITTED}"),
    }

    println!("xtask btrfs-crash-smoke: boot 2 (verify after the kill)");
    match boot_until(
        &args.build,
        &kernel,
        &with("narf.btrfs_crash=verify"),
        &[OK, FAIL],
        timeout,
    )?
    .as_deref()
    {
        Some(OK) => {}
        Some(other) => bail!("btrfs-crash-smoke: verify boot reported {other}"),
        None => bail!("btrfs-crash-smoke: verify boot never reported a verdict"),
    }
    std::env::set_var("XTASK_QEMU_APPEND", prior_append);

    let check = Command::new("btrfs")
        .args(["check", "--readonly", "--check-data-csum"])
        .arg(&image)
        .output()
        .context("run host `btrfs check`")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    println!("{text}");
    if !check.status.success() || !text.contains("no error found") {
        bail!("btrfs-crash-smoke: host `btrfs check` failed on the killed image");
    }
    println!("xtask btrfs-crash-smoke: OK — fsynced data survived SIGKILL, image check-clean");
    Ok(())
}
