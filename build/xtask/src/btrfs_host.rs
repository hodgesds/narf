//! `cargo xtask btrfs-host-rw`: the host-side (no QEMU) root-rw btrfs
//! harness, `verification/btrfs-host`.
//!
//! Builds the `narf-btrfs-host` binary for the host (release: the workload
//! reads every file back through the driver several times) and runs it. The
//! driver runs in-process against image files; Linux userspace
//! (`mkfs.btrfs`, `btrfs check`, `btrfs restore`) judges the results. No
//! privileges, loop devices or host disks are involved.

use std::process::Command;

use anyhow::{bail, Context, Result};

/// Options for the host btrfs harness (forwarded to `narf-btrfs-host`).
#[derive(clap::Args, Clone, Debug, Default)]
pub struct Args {
    /// First workload seed.
    #[arg(long)]
    pub seed: Option<u64>,
    /// Seeds to run per scenario.
    #[arg(long)]
    pub seeds: Option<u64>,
    /// Operations in the `root` scenario (the others scale from it).
    #[arg(long)]
    pub ops: Option<u64>,
    /// Crash cut points in the `root` scenario (0 disables the crash pass).
    #[arg(long)]
    pub cuts: Option<u64>,
    /// Crash-test every flush boundary plus two random cuts per window.
    #[arg(long)]
    pub exhaustive: bool,
    /// Comma-separated scenarios (regress,root,snapshots,lba4k,gate).
    #[arg(long)]
    pub scenario: Option<String>,
    /// Concurrent `btrfs check` processes in the crash pass.
    #[arg(long)]
    pub jobs: Option<u64>,
    /// Keep the images of passing runs (in target/btrfs-host).
    #[arg(long)]
    pub keep: bool,
    /// Build the harness with the dev profile instead of release.
    #[arg(long)]
    pub debug: bool,
}

/// The `narf-btrfs-host` command line for `args`.
pub fn harness_args(args: &Args) -> Vec<String> {
    let mut v = Vec::new();
    let mut num = |flag: &str, val: Option<u64>| {
        if let Some(n) = val {
            v.push(flag.to_string());
            v.push(n.to_string());
        }
    };
    num("--seed", args.seed);
    num("--seeds", args.seeds);
    num("--ops", args.ops);
    num("--cuts", args.cuts);
    num("--jobs", args.jobs);
    if let Some(s) = &args.scenario {
        v.push("--scenario".into());
        v.push(s.clone());
    }
    if args.exhaustive {
        v.push("--exhaustive".into());
    }
    if args.keep {
        v.push("--keep".into());
    }
    v
}

/// The cargo invocation that builds and runs the harness.
pub fn cargo_command(args: &Args) -> Command {
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.args([
        "run",
        "--package",
        "narf-btrfs-host",
        "--bin",
        "narf-btrfs-host",
    ]);
    if !args.debug {
        c.arg("--release");
    }
    c.arg("--").args(harness_args(args));
    c
}

pub fn run(args: &Args) -> Result<()> {
    for tool in ["mkfs.btrfs", "btrfs", "unshare"] {
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !found {
            bail!("btrfs-host-rw needs `{tool}` on PATH (btrfs-progs, util-linux)");
        }
    }
    let root = super::workspace_root()?;
    let status = cargo_command(args)
        .current_dir(&root)
        .status()
        .context("run narf-btrfs-host")?;
    if !status.success() {
        bail!("btrfs-host-rw failed ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_args_forward_nothing() {
        assert!(harness_args(&Args::default()).is_empty());
        let c = cargo_command(&Args::default());
        let argv: Vec<_> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            [
                "run",
                "--package",
                "narf-btrfs-host",
                "--bin",
                "narf-btrfs-host",
                "--release",
                "--"
            ]
        );
    }

    #[test]
    fn flags_are_forwarded() {
        let a = Args {
            seed: Some(7),
            seeds: Some(3),
            ops: Some(500),
            cuts: Some(0),
            exhaustive: true,
            scenario: Some("root,gate".into()),
            jobs: Some(2),
            keep: true,
            debug: true,
        };
        assert_eq!(
            harness_args(&a),
            [
                "--seed",
                "7",
                "--seeds",
                "3",
                "--ops",
                "500",
                "--cuts",
                "0",
                "--jobs",
                "2",
                "--scenario",
                "root,gate",
                "--exhaustive",
                "--keep"
            ]
        );
        assert!(!cargo_command(&a).get_args().any(|x| x == "--release"));
    }
}
