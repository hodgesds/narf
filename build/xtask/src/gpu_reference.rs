//! Explicit, revision-pinned Linux source checks for the native GPU ports.
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Debug, Clone, Parser)]
pub struct Args {
    /// Clean Linux Git checkout to use; never defaults to a host source tree.
    #[arg(long)]
    linux_tree: PathBuf,
    /// Full Linux commit object ID (40 or 64 hexadecimal digits).
    #[arg(long, value_parser = full_revision)]
    linux_revision: String,
}

fn full_revision(value: &str) -> std::result::Result<String, String> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected a full Linux commit object ID (40 or 64 hexadecimal digits)".into());
    }
    Ok(value.to_ascii_lowercase())
}

pub fn run(args: &Args, root: &Path) -> Result<()> {
    let status = Command::new("bash")
        .arg(root.join("drivers/gpu/tests/check-reference.sh"))
        .arg("--linux-tree")
        .arg(&args.linux_tree)
        .arg("--linux-revision")
        .arg(&args.linux_revision)
        .status()
        .context("run the revision-pinned GPU reference checks")?;
    if !status.success() {
        bail!("GPU reference checks failed ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "narf-gpu-reference-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn git(&self, args: &[&str]) -> String {
            let output = Command::new("git")
                .arg("-C")
                .arg(self.0.join("linux tree"))
                .args([
                    "-c",
                    "user.name=NARF test",
                    "-c",
                    "user.email=test@example.invalid",
                ])
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{args:?}: {output:?}");
            String::from_utf8(output.stdout).unwrap().trim().into()
        }
        fn setup(&self) -> Args {
            let linux = self.0.join("linux tree");
            fs::create_dir_all(linux.join("drivers/gpu/drm")).unwrap();
            fs::write(linux.join("source.h"), "reference\n").unwrap();
            self.git(&["init", "--quiet"]);
            self.git(&["add", "."]);
            self.git(&["commit", "--quiet", "-m", "reference fixture"]);
            let tests = self.0.join("drivers/gpu/tests");
            fs::create_dir_all(tests.join("fixture")).unwrap();
            fs::write(
                tests.join("check-reference.sh"),
                include_str!("../../../drivers/gpu/tests/check-reference.sh"),
            )
            .unwrap();
            fs::write(
                tests.join("fixture/check.sh"),
                "#!/bin/bash\nset -eu\n[ \"$1\" = \"$LINUX_SRC\" ]\n[ -f \"$1/source.h\" ]\nprintf '%s\\n' \"$1\" > ran\n",
            )
            .unwrap();
            Args {
                linux_tree: linux,
                linux_revision: self.git(&["rev-parse", "HEAD"]),
            }
        }
        fn ran(&self) -> bool {
            self.0.join("drivers/gpu/tests/fixture/ran").is_file()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn requires_explicit_tree_and_full_commit() {
        assert!(Args::try_parse_from(["gpu-reference"]).is_err());
        assert!(Args::try_parse_from([
            "gpu-reference",
            "--linux-tree",
            "/tmp/linux",
            "--linux-revision",
            "HEAD"
        ])
        .is_err());
        assert!(full_revision(&"a".repeat(40)).is_ok());
        assert!(full_revision(&"B".repeat(64)).is_ok());
        assert!(full_revision(&"a".repeat(39)).is_err());
        assert!(full_revision(&"z".repeat(40)).is_err());
    }

    #[test]
    fn verifies_revision_and_runs_discovered_checks_with_explicit_tree() {
        let fixture = Fixture::new();
        let args = fixture.setup();
        run(&args, &fixture.0).unwrap();
        assert!(fixture.ran());
        assert!(fixture.git(&["status", "--porcelain"]).is_empty());
    }

    #[test]
    fn rejects_mismatch_and_dirty_sources_before_running_any_check() {
        for kind in ["revision", "tracked", "untracked", "ignored"] {
            let fixture = Fixture::new();
            let mut args = fixture.setup();
            match kind {
                "revision" => args.linux_revision = "0".repeat(40),
                "tracked" => fs::write(args.linux_tree.join("source.h"), "changed\n").unwrap(),
                "untracked" => fs::write(args.linux_tree.join("extra.h"), "extra\n").unwrap(),
                "ignored" => {
                    fs::write(args.linux_tree.join(".git/info/exclude"), "extra.h\n").unwrap();
                    fs::write(args.linux_tree.join("extra.h"), "extra\n").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(run(&args, &fixture.0).is_err(), "{kind}");
            assert!(!fixture.ran(), "{kind}");
        }
    }

    #[test]
    fn propagates_harness_failure_and_detects_reference_mutation() {
        for script in ["exit 7\n", "printf 'changed\\n' >> \"$1/source.h\"\n"] {
            let fixture = Fixture::new();
            let args = fixture.setup();
            fs::write(fixture.0.join("drivers/gpu/tests/fixture/check.sh"), script).unwrap();
            assert!(run(&args, &fixture.0).is_err());
        }
    }
}
