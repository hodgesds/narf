//! `cargo xtask ext4-host-rw`: the host-side (no QEMU) ext4 write harness,
//! `verification/ext4-host`.
//!
//! Builds the `narf-ext4-host` binary for the host (release by default) and
//! runs it. The driver runs in-process against image files made by
//! `mkfs.ext4 -d`; e2fsprogs (`e2fsck -fn`, `debugfs`, `dumpe2fs`) judges the
//! results. No privileges, loop devices or host disks are involved.

use std::process::Command;

use anyhow::{bail, Context, Result};

/// Options for the host ext4 harness (forwarded to `narf-ext4-host`).
#[derive(clap::Args, Clone, Debug, Default)]
pub struct Args {
    /// First workload seed.
    #[arg(long)]
    pub seed: Option<u64>,
    /// Seeds to run per scenario.
    #[arg(long)]
    pub seeds: Option<u64>,
    /// Operations per run.
    #[arg(long)]
    pub ops: Option<u64>,
    /// Comma-separated scenarios (see `narf-ext4-host --help`).
    #[arg(long)]
    pub scenario: Option<String>,
    /// Keep the images of passing runs (in target/ext4-host).
    #[arg(long)]
    pub keep: bool,
    /// Build the harness with the dev profile instead of release.
    #[arg(long)]
    pub debug: bool,
}

/// The `narf-ext4-host` command line for `args`.
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
    if let Some(s) = &args.scenario {
        v.push("--scenario".into());
        v.push(s.clone());
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
        "narf-ext4-host",
        "--bin",
        "narf-ext4-host",
    ]);
    if !args.debug {
        c.arg("--release");
    }
    c.arg("--").args(harness_args(args));
    c
}

pub fn run(args: &Args) -> Result<()> {
    for tool in ["mkfs.ext4", "e2fsck", "debugfs", "dumpe2fs"] {
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !found {
            bail!("ext4-host-rw needs `{tool}` on PATH (e2fsprogs)");
        }
    }
    let root = super::workspace_root()?;
    let status = cargo_command(args)
        .current_dir(&root)
        .status()
        .context("run narf-ext4-host")?;
    if !status.success() {
        bail!("ext4-host-rw failed ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_args_forward_nothing() {
        assert!(harness_args(&Args::default()).is_empty());
        let argv: Vec<_> = cargo_command(&Args::default())
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            [
                "run",
                "--package",
                "narf-ext4-host",
                "--bin",
                "narf-ext4-host",
                "--release",
                "--"
            ]
        );
    }

    #[test]
    fn flags_are_forwarded() {
        let args = Args {
            seed: Some(3),
            seeds: Some(4),
            ops: Some(500),
            scenario: Some("baseline".into()),
            keep: true,
            debug: false,
        };
        assert_eq!(
            harness_args(&args),
            [
                "--seed",
                "3",
                "--seeds",
                "4",
                "--ops",
                "500",
                "--scenario",
                "baseline",
                "--keep"
            ]
        );
    }
}
