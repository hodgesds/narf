//! Lint explicitly selected packages with the kernel's feature contexts.
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser, Clone)]
pub struct Args {
    #[arg(long, value_parser = ["x86_64", "aarch64", "host"])]
    arch: String,
    /// JSON array from `xtask affected`'s clippy_crates or host_clippy_crates.
    #[arg(long)]
    packages: String,
    /// Print commands without running Clippy (metadata is still resolved).
    #[arg(long)]
    dry_run: bool,
}

const CONTEXTS: &[&str] = &[
    "boot-smoke,cgroup-all,bpf-idle,bpf-leds",
    "boot-smoke,cgroup-all,bpf-idle,bpf-leds,container",
    "user-mode-e2e",
];

/// Cargo's unit graph separates host build dependencies from target code;
/// metadata's resolve graph merges their features and can incorrectly enable
/// `std` for a bare-metal dependency. Only check units on this target count.
fn lint_features(
    metadata: &serde_json::Value,
    graph: &serde_json::Value,
    target: &str,
    selected: &[String],
) -> Result<BTreeSet<String>> {
    let packages = metadata["packages"]
        .as_array()
        .context("metadata packages")?;
    let units = graph["units"].as_array().context("Cargo unit graph")?;
    let target_unit = |u: &serde_json::Value| {
        u["platform"].as_str() == Some(target) && u["mode"].as_str() == Some("check")
    };
    let mut features = BTreeSet::new();
    for name in selected {
        let pkg = packages
            .iter()
            .find(|p| p["name"].as_str() == Some(name))
            .with_context(|| format!("unknown workspace package {name}"))?;
        let unit = units
            .iter()
            .find(|u| u["pkg_id"] == pkg["id"] && target_unit(u))
            .with_context(|| format!("no target check unit for {name}"))?;
        let mut add = |prefix: &str, unit: &serde_json::Value| {
            for feature in unit["features"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|f| f.as_str())
            {
                features.insert(format!("{prefix}/{feature}"));
            }
        };
        add(name, unit);
        // Preserve frame-unified features on direct dependencies, without
        // turning those dependencies into primary lint targets.
        for edge in unit["dependencies"].as_array().into_iter().flatten() {
            let index = edge["index"].as_u64().context("dependency unit index")? as usize;
            let dependency = units.get(index).context("dependency unit")?;
            if !target_unit(dependency) {
                continue;
            }
            let extern_name = edge["extern_crate_name"]
                .as_str()
                .context("dependency alias")?;
            let alias = pkg["dependencies"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|d| d["rename"].as_str().or_else(|| d["name"].as_str()))
                .find(|alias| alias.replace('-', "_") == extern_name)
                .with_context(|| format!("manifest alias for {extern_name}"))?;
            add(alias, dependency);
        }
    }
    Ok(features)
}

fn read_json(cmd: &mut Command) -> Result<serde_json::Value> {
    let output = cmd.output().with_context(|| format!("run {cmd:?}"))?;
    if !output.status.success() {
        bail!(
            "{cmd:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("Cargo JSON output")
}

pub fn run(args: &Args, root: &Path) -> Result<()> {
    let selected: Vec<String> =
        serde_json::from_str(&args.packages).context("--packages must be a JSON array")?;
    if selected.is_empty() {
        return Ok(());
    }
    if args.arch == "host" {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(root)
            .args(clippy_args(None, &selected, BTreeSet::new()));
        eprintln!("clippy-changed (host): {cmd:?}");
        if !args.dry_run && !cmd.status().context("run host Clippy")?.success() {
            bail!("host Clippy failed");
        }
        return Ok(());
    }
    let target = format!("{}-unknown-none", args.arch);
    let metadata = read_json(Command::new("cargo").current_dir(root).args([
        "metadata",
        "--locked",
        "--no-deps",
        "--format-version=1",
    ]))?;
    let mut seen = BTreeSet::new();
    for context in CONTEXTS {
        let frame_features = context
            .split(',')
            .map(|f| format!("narf-frame/{f}"))
            .collect::<Vec<_>>()
            .join(",");
        // Planning only: --unit-graph does not compile or lint frame. Include
        // selected unlinked drivers/modules so their own defaults also resolve.
        let mut planning = Command::new("cargo");
        planning.current_dir(root).args([
            "check",
            "--locked",
            "-p",
            "narf-frame",
            "--target",
            &target,
            "--features",
            &frame_features,
            "-Zunstable-options",
            "--unit-graph",
        ]);
        for package in &selected {
            if package != "narf-frame" {
                planning.args(["-p", package]);
            }
        }
        let graph = read_json(&mut planning)?;
        let features = lint_features(&metadata, &graph, &target, &selected)?;
        // Identical selected/dependency feature contexts need only one pass.
        if !seen.insert(features.clone()) {
            continue;
        }
        let mut cmd = Command::new("cargo");
        cmd.current_dir(root)
            .args(clippy_args(Some(&target), &selected, features));
        eprintln!("clippy-changed ({context}): {cmd:?}");
        if !args.dry_run && !cmd.status().context("run targeted Clippy")?.success() {
            bail!("targeted Clippy failed ({context})");
        }
    }
    Ok(())
}

fn clippy_args(
    target: Option<&str>,
    selected: &[String],
    features: BTreeSet<String>,
) -> Vec<String> {
    let mut args = ["clippy", "--locked", "--no-deps"]
        .map(str::to_string)
        .to_vec();
    if let Some(target) = target {
        args.extend(
            [
                "--target",
                target,
                "-Zbuild-std=core,compiler_builtins,alloc",
                "-Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128",
            ]
            .map(str::to_string),
        );
    } else {
        args.push("--all-targets".into());
    }
    for package in selected {
        args.extend(["-p".into(), package.clone()]);
    }
    if !features.is_empty() {
        args.extend([
            "--features".into(),
            features.into_iter().collect::<Vec<_>>().join(","),
        ]);
    }
    args.extend(["--".into(), "-D".into(), "warnings".into()]);
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_features_preserve_aliases_without_linting_dependencies() {
        let metadata = serde_json::json!({"packages": [
            {"id": "a", "name": "narf-audio", "dependencies": [
                {"name": "narf-userspace", "rename": "linux"},
                {"name": "serde", "rename": null}
            ]}
        ]});
        let graph = serde_json::json!({"units": [
            {"pkg_id": "a", "platform": "aarch64-unknown-none", "mode": "check",
             "features": ["kernel-test"], "dependencies": [
                 {"index": 1, "extern_crate_name": "linux"},
                 {"index": 2, "extern_crate_name": "serde"},
                 {"index": 3, "extern_crate_name": "build_script_build"}
             ]},
            {"pkg_id": "u", "platform": "aarch64-unknown-none", "mode": "check", "features": ["container", "kernel-test"]},
            {"pkg_id": "s", "platform": "aarch64-unknown-none", "mode": "check", "features": ["alloc"]},
            {"pkg_id": "a", "platform": "aarch64-unknown-none", "mode": "run-custom-build", "features": ["std"]},
            {"pkg_id": "s", "platform": null, "mode": "build", "features": ["std", "default"]}
        ]});
        let selected = vec!["narf-audio".into()];
        let features = lint_features(&metadata, &graph, "aarch64-unknown-none", &selected).unwrap();
        assert!(features.contains("narf-audio/kernel-test"));
        assert!(features.contains("linux/container"));
        assert!(features.contains("serde/alloc"));
        assert!(!features.contains("serde/std"));
        assert!(!features.contains("narf-userspace/container"));
        let args = clippy_args(Some("aarch64-unknown-none"), &selected, features);
        let packages: Vec<_> = args
            .windows(2)
            .filter(|w| w[0] == "-p")
            .map(|w| w[1].as_str())
            .collect();
        assert_eq!(packages, ["narf-audio"]);
        assert!(args.contains(&"--no-deps".into()));
        assert!(args.ends_with(&["--".into(), "-D".into(), "warnings".into()]));
        assert!(lint_features(
            &metadata,
            &graph,
            "aarch64-unknown-none",
            &["missing".into()]
        )
        .is_err());
    }
}
