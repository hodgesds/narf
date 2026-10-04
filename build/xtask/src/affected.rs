//! `cargo xtask affected` — compute which CI jobs and kernel-test
//! subsystems a change can affect, so CI can skip work a diff cannot
//! influence.
//!
//! The kernel is a single bootable binary (`narf-frame`) that links ~all
//! workspace crates, so the dominant CI cost is compilation, and the big
//! lever is skipping *orthogonal jobs* (a `drivers/gpu` change need not run
//! `net-smoke`) rather than splitting the build. This command implements a
//! deliberately conservative over-approximation:
//!
//! 1. `git diff` the merge-base with the base ref → changed files.
//! 2. Map each file to its owning workspace crate (longest manifest-dir
//!    prefix), via `cargo metadata --no-deps`.
//! 3. Expand to the reverse-transitive closure over workspace-local
//!    dependency edges (if crate X changed, everything that depends on X is
//!    affected — this is how a public-API change in one subsystem pulls in
//!    the subsystems that call it).
//! 4. Trip `full = true` (run everything, exactly like today) when the
//!    change touches build infrastructure, a hub crate, an unrecognized
//!    path, or when the CI event is a nightly / manual run.
//!
//! The policy (which crates are hubs, which crates map to which job) lives
//! in this one file so there is a single place to reason about correctness.
//! Everything below the I/O helpers is pure and unit-tested in `host-test`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

/// Crates whose public surface is depended on so broadly that a change
/// almost certainly reaches the whole tree. Touching one forces a full run
/// rather than trusting the closure to be complete.
const HUB_CRATES: &[&str] = &[
    "narf-lib",
    "narf-arch",
    "narf-kernel-test",
    "narf-capabilities",
    "narf-memory",
    "narf-abi",
    // Owns the runner and cross-cutting integration harnesses.
    "narf-verification",
];

/// A change reaching any of these (in the reverse closure) exercises the
/// linux-compat userspace execution path that `musl-demo` covers.
const MUSL_CRATES: &[&str] = &[
    "narf-userspace",
    "narf-filesystem",
    "narf-memory",
    "narf-scheduler",
    "narf-abi",
];

/// A change reaching any of these exercises the off-box networking path
/// that `net-smoke` covers.
const NET_CRATES: &[&str] = &["narf-net", "narf-ipc", "narf-io", "narf-drivers-net"];

/// The final bootable binary. Its presence in the closure is the signal
/// that a real kernel crate changed (as opposed to xtask/docs), which is
/// what the boot-based gates (`boot-smoke`, `kernel-test`) key on.
const KERNEL_BIN: &str = "narf-frame";

/// The all-crates test aggregator; changed whenever any tested crate is.
const VERIFICATION: &str = "narf-verification";

/// Path prefixes/basenames that force a full run: touching the build
/// system or CI itself invalidates the whole affected computation.
fn is_infra_path(rel: &str) -> bool {
    rel == "Cargo.toml"
        || rel == "Cargo.lock"
        || rel == "rust-toolchain.toml"
        || rel == ".cargo/config.toml"
        || rel == ".cargo/config"
        || rel.starts_with(".github/")
        || rel.starts_with("build/xtask/")
        || rel == "run_ci_locally.sh"
}

/// Documentation / metadata files that affect no build output. These are
/// simply ignored (contribute no crate and no job beyond the always-on
/// ones) rather than tripping the conservative "unknown ⇒ full" default.
fn is_ignorable_path(rel: &str) -> bool {
    if rel.starts_with("docs/") || rel.starts_with("notes/") {
        return true;
    }
    let base = rel.rsplit('/').next().unwrap_or(rel);
    matches!(
        base,
        "LICENSE" | "README.md" | "ROADMAP.md" | "STATUS.md" | "AGENTS.md"
    ) || base.ends_with(".md")
}

/// One workspace crate: its cargo package name, its directory relative to
/// the workspace root, and the names of the *workspace-local* crates it
/// depends on (forward edges).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrateInfo {
    pub name: String,
    /// Directory relative to workspace root, e.g. `drivers/net`. Never has
    /// a trailing slash.
    pub dir: String,
    pub deps: Vec<String>,
}

/// The output format for [`AffectedArgs`].
#[derive(Clone, Copy, clap::ValueEnum, Default, Debug)]
pub enum OutputFormat {
    /// Pretty JSON to stdout (default; human + tooling readable).
    #[default]
    Json,
    /// `name=value` lines. With `--github`, appended to `$GITHUB_OUTPUT`.
    Github,
}

#[derive(Parser, Clone)]
pub struct AffectedArgs {
    /// Base git ref. PRs diff from its merge-base with --head; pushes diff
    /// the two refs directly so force-push removals are included.
    #[arg(long, default_value = "origin/main")]
    base: String,

    /// The current side of the diff.
    #[arg(long, default_value = "HEAD")]
    head: String,

    /// CI event name. Defaults to `$GITHUB_EVENT_NAME`, else
    /// `pull_request`. Nightly/manual runs force the complete matrix.
    /// For pushes, pass the event's before SHA as --base.
    #[arg(long)]
    event: Option<String>,

    /// Force a full run regardless of the diff (the `ci-full` PR-label
    /// escape hatch wires to this).
    #[arg(long)]
    force_full: bool,

    /// Emit to `$GITHUB_OUTPUT` (implies `--format github`). No-op locally
    /// if the variable is unset (falls back to stdout).
    #[arg(long)]
    github: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

    /// Bypass git and treat these as the changed files (testing / manual).
    /// Repeatable.
    #[arg(long = "changed-file")]
    changed_files: Vec<String>,
}

/// The computed decision. Pure output of [`plan`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub full: bool,
    pub reasons: Vec<String>,
    pub crates: BTreeSet<String>,
    pub changed_crates: BTreeSet<String>,
    pub clippy_crates: BTreeSet<String>,
    pub host_clippy_crates: BTreeSet<String>,
    pub run_uefi: bool,
    pub run_large_memory: bool,
    pub run_xapic: bool,
    pub run_virtio_mmio: bool,
    pub run_user_mode: bool,
    pub subsystems: BTreeSet<String>,
    pub run_clippy: bool,
    pub clippy_arches: Vec<String>,
    pub run_boot_smoke: bool,
    pub run_kernel_test: bool,
    pub run_musl_demo: bool,
    pub run_net_smoke: bool,
    pub run_feature_matrix: bool,
}

impl Plan {
    /// The set of gate job names to run, always including the cheap
    /// always-on ones.
    pub fn jobs(&self) -> Vec<String> {
        let mut jobs = vec!["fmt".to_string(), "host-tests".to_string()];
        let mut push = |cond: bool, name: &str| {
            if cond {
                jobs.push(name.to_string());
            }
        };
        push(self.run_clippy, "clippy-kernel");
        push(!self.host_clippy_crates.is_empty(), "clippy-host");
        push(self.run_uefi, "uefi-loader");
        push(self.run_boot_smoke, "boot-smoke");
        push(self.run_kernel_test, "kernel-test");
        push(self.run_musl_demo, "musl-demo");
        push(self.run_net_smoke, "net-smoke");
        push(self.run_feature_matrix, "feature-matrix");
        jobs
    }
}

/// Map a changed file (relative to workspace root) to the name of the
/// owning crate, by longest directory-prefix match on crate dirs. Returns
/// `None` for files not under any crate.
pub fn file_to_crate<'a>(rel: &str, crates: &'a [CrateInfo]) -> Option<&'a str> {
    let mut best: Option<&CrateInfo> = None;
    for c in crates {
        let under = c.dir.is_empty() || rel == c.dir || rel.starts_with(&format!("{}/", c.dir));
        if !under {
            continue;
        }
        match best {
            Some(b) if b.dir.len() >= c.dir.len() => {}
            _ => best = Some(c),
        }
    }
    best.map(|c| c.name.as_str())
}

/// Reverse-transitive closure: every crate that transitively depends on
/// any seed, plus the seeds themselves.
pub fn reverse_closure(seeds: &BTreeSet<String>, crates: &[CrateInfo]) -> BTreeSet<String> {
    // Build reverse adjacency: dep -> [crates that declare it].
    let mut rev: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for c in crates {
        for d in &c.deps {
            rev.entry(d.as_str()).or_default().push(c.name.as_str());
        }
    }
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = seeds.iter().cloned().collect();
    while let Some(n) = stack.pop() {
        if !out.insert(n.clone()) {
            continue;
        }
        if let Some(dependents) = rev.get(n.as_str()) {
            for &r in dependents {
                if !out.contains(r) {
                    stack.push(r.to_string());
                }
            }
        }
    }
    out
}

/// Collapse a tag set so that a tag is dropped when a strict prefix of it
/// (on a `/` boundary) is also present — `filesystem` subsumes
/// `filesystem/page_cache` under the kernel-test prefix filter.
fn collapse_tags(tags: BTreeSet<String>) -> BTreeSet<String> {
    let all: Vec<String> = tags.iter().cloned().collect();
    all.iter()
        .filter(|t| {
            !all.iter()
                .any(|p| *p != **t && t.starts_with(&format!("{p}/")))
        })
        .cloned()
        .collect()
}

/// The pure decision function. `tag_map` maps crate name → the kernel-test
/// subsystem tags registered in that crate.
pub fn plan(
    changed_files: &[String],
    crates: &[CrateInfo],
    tag_map: &BTreeMap<String, BTreeSet<String>>,
    event: &str,
    force_full: bool,
) -> Plan {
    let mut p = Plan::default();

    // Global full-run triggers.
    if force_full {
        p.full = true;
        p.reasons
            .push("forced (--force-full / ci-full label)".into());
    }
    if matches!(event, "schedule" | "workflow_dispatch") {
        p.full = true;
        p.reasons
            .push(format!("event `{event}` always runs the full matrix"));
    }
    if changed_files.is_empty() && !p.full {
        // Nothing to diff: conservatively run everything rather than
        // silently gate on an empty change set (e.g. a broken base ref).
        p.full = true;
        p.reasons
            .push("empty changed-file set — running full as a safe default".into());
    }

    // Classify each changed file.
    let mut seeds: BTreeSet<String> = BTreeSet::new();
    let mut embedded = false;
    let mut cargo_toml_touched = false;
    let mut lint_all =
        force_full || matches!(event, "schedule" | "workflow_dispatch") || changed_files.is_empty();
    for f in changed_files {
        let base = f.rsplit('/').next().unwrap_or(f);
        if base == "Cargo.toml" && f != "Cargo.toml" {
            cargo_toml_touched = true;
        }
        if is_infra_path(f) {
            p.full = true;
            p.reasons.push(format!("infra path `{f}`"));
            lint_all |= !f.starts_with("build/xtask/");
        }
        if is_ignorable_path(f) {
            continue;
        }
        // These separately built images are embedded by verification/build.rs;
        // Cargo's workspace graph cannot describe those build-script edges.
        if embedded_input(f) {
            embedded = true;
            // Isolated images are not members of their enclosing userspace
            // crate. Their consumer is recorded below as a build dependency.
            if !f.starts_with("user-runtime/") {
                continue;
            }
        }
        if f.starts_with("build/uefi-loader/") {
            p.run_uefi = true;
            continue;
        }
        if f.ends_with("/Cargo.toml")
            && !crates.iter().any(|c| f == &format!("{}/Cargo.toml", c.dir))
            && !embedded_input(f)
        {
            p.full = true;
            lint_all = true;
            p.reasons.push(format!("removed or unknown manifest `{f}`"));
        }
        match file_to_crate(f, crates) {
            Some(name) => {
                seeds.insert(name.to_string());
            }
            None if embedded_input(f) => {}
            None => {
                // Unrecognized, non-doc path: be safe.
                p.full = true;
                p.reasons.push(format!("unmapped path `{f}` ⇒ full"));
                lint_all = true;
            }
        }
    }

    // Hub crate directly touched ⇒ full.
    for s in &seeds {
        if HUB_CRATES.contains(&s.as_str()) {
            p.full = true;
            p.reasons.push(format!("hub crate `{s}` changed ⇒ full"));
        }
    }

    p.changed_crates = seeds.clone();
    if embedded {
        seeds.insert(VERIFICATION.into());
    }
    let closure = reverse_closure(&seeds, crates);
    let has = |n: &str| closure.contains(n);
    let has_any = |set: &[&str]| set.iter().any(|n| closure.contains(*n));

    let lint = if lint_all {
        crates.iter().map(|c| c.name.clone()).collect()
    } else {
        p.changed_crates.clone()
    };
    // Host tools are the only std binaries in this workspace. Unlinked
    // driver/module crates still need bare-metal linting when they change.
    p.host_clippy_crates = lint
        .iter()
        .filter(|c| matches!(c.as_str(), "xtask" | "cargo-narf"))
        .cloned()
        .collect();
    p.clippy_crates = lint.difference(&p.host_clippy_crates).cloned().collect();
    p.run_clippy = !p.clippy_crates.is_empty();
    // Any kernel crate can contain architecture-specific code. Keep both
    // targets; package selection, rather than path guesses, reduces lint work.
    p.clippy_arches = vec!["x86_64".into(), "aarch64".into()];
    p.run_uefi |= lint_all;
    p.run_large_memory =
        p.full || has_any(&["narf-memory", "narf-boot", "narf-arch"]) || seeds.contains(KERNEL_BIN);
    p.run_xapic = p.full
        || has_any(&[
            "narf-interrupts",
            "narf-memory",
            "narf-scheduler",
            "narf-arch",
        ])
        || seeds.contains(KERNEL_BIN);
    p.run_virtio_mmio = p.full
        || has_any(&["narf-drivers-virtio", "narf-bus", "narf-io", "narf-arch"])
        || seeds.contains(KERNEL_BIN)
        || seeds.contains(VERIFICATION);
    p.run_user_mode = p.full
        || has_any(MUSL_CRATES)
        || seeds.contains(KERNEL_BIN)
        || seeds.contains(VERIFICATION);

    if p.full {
        p.crates = crates.iter().map(|c| c.name.clone()).collect();
        p.run_boot_smoke = true;
        p.run_kernel_test = true;
        p.run_musl_demo = true;
        p.run_net_smoke = true;
        p.run_feature_matrix = true;
        return p;
    }
    p.crates = closure.clone();

    // Boot-based gates: only when a real kernel crate is in the closure
    // (frame links ~everything, so frame ∈ closure ⟺ a kernel crate
    // changed; xtask/doc-only changes never pull it in).
    p.run_boot_smoke = has(KERNEL_BIN) || p.run_uefi;
    p.run_kernel_test = has(KERNEL_BIN) || has(VERIFICATION);

    // musl-demo: linux-compat userspace execution path, plus the C libc
    // dir (not a cargo member, so keyed by path).
    let libc_touched = changed_files.iter().any(|f| f.starts_with("narf-libc/"));
    p.run_musl_demo = has_any(MUSL_CRATES) || libc_touched || embedded;

    // net-smoke: off-box networking path.
    p.run_net_smoke = has_any(NET_CRATES);

    // feature-matrix: feature forwarding lives in member Cargo.toml files.
    p.run_feature_matrix = cargo_toml_touched;

    // Preserve all dependent test tags, then compact equivalent prefixes.
    // Fall back to the whole suite only if the byte budget is exceeded.
    if p.run_kernel_test {
        let mut tags: BTreeSet<String> = BTreeSet::new();
        for c in &closure {
            if let Some(t) = tag_map.get(c) {
                tags.extend(t.iter().cloned());
            }
        }
        let universe = tag_map.values().flatten().cloned().collect();
        let collapsed = compact_tags(tags, &universe);
        let filter_bytes = collapsed.iter().map(|t| t.len() + 1).sum::<usize>();
        if filter_bytes > MAX_SUBSYSTEM_FILTER_BYTES {
            p.reasons.push(format!(
                "subsystem filter needs {} bytes > budget {} — running the full kernel-test suite",
                filter_bytes, MAX_SUBSYSTEM_FILTER_BYTES
            ));
        } else {
            p.subsystems = collapsed;
        }
    }

    p
}

// Leave room for the rest of the kernel command line on both boot paths.
const MAX_SUBSYSTEM_FILTER_BYTES: usize = 1024;

/// Collapse a common prefix only if it admits no test outside the selected
/// set. A crate with 40 USB tags becomes `drivers/usb`, even when there is
/// no test registered at that exact parent. Never invent a broad `drivers`
/// filter that would also run unrelated drivers.
fn compact_tags(tags: BTreeSet<String>, universe: &BTreeSet<String>) -> BTreeSet<String> {
    let selected = |tag: &str| {
        tags.iter()
            .any(|t| tag == t || tag.starts_with(&format!("{t}/")))
    };
    let mut compacted = BTreeSet::new();
    for tag in &tags {
        let mut chosen = tag.as_str();
        for (i, _) in tag.match_indices('/') {
            let prefix = &tag[..i];
            if universe
                .iter()
                .filter(|t| *t == prefix || t.starts_with(&format!("{prefix}/")))
                .all(|t| selected(t))
            {
                chosen = prefix;
                break;
            }
        }
        compacted.insert(chosen.to_string());
    }
    collapse_tags(compacted)
}

fn embedded_input(path: &str) -> bool {
    [
        "user-runtime/",
        "narf-libc/",
        "userspace/init/",
        "userspace/shell/",
        "userspace/testbin/",
        "userspace/getty/",
        "userspace/login-core/",
        "userspace/coreutils/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// I/O layer: git, cargo metadata, source scan, and output.
// ---------------------------------------------------------------------------

/// Load the workspace crate graph via `cargo metadata --no-deps`.
fn load_workspace(root: &Path) -> Result<Vec<CrateInfo>> {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version=1", "--no-deps"])
        .current_dir(root)
        .output()
        .context("failed to run `cargo metadata`")?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("parsing cargo metadata JSON")?;
    workspace_crates(&json)
}

fn workspace_crates(json: &serde_json::Value) -> Result<Vec<CrateInfo>> {
    let ws_root = json
        .get("workspace_root")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let members: BTreeSet<String> = json
        .get("workspace_members")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let mut crates = Vec::new();
    for pkg in json
        .get("packages")
        .and_then(|v| v.as_array())
        .context("cargo metadata: no packages array")?
    {
        let id = pkg.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        if !members.is_empty() && !members.contains(id) {
            continue;
        }
        let name = pkg
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let manifest = pkg
            .get("manifest_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        // Directory relative to the workspace root, no trailing slash.
        let dir = Path::new(manifest)
            .parent()
            .context("manifest parent")?
            .strip_prefix(&ws_root)
            .context("workspace member outside root")?
            .to_str()
            .context("non-UTF-8 crate directory")?
            .to_string();
        let deps = pkg
            .get("dependencies")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter(|d| d.get("path").and_then(|p| p.as_str()).is_some())
                    .filter_map(|d| d.get("name").and_then(|n| n.as_str()).map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        crates.push(CrateInfo { name, dir, deps });
    }
    Ok(crates)
}

/// The changed files between the merge-base of `base` and `head`.
fn git_changed_files(root: &Path, base: &str, head: &str, event: &str) -> Result<Vec<String>> {
    let range = if event == "push" {
        format!("{base}..{head}")
    } else {
        let mb = Command::new("git")
            .args(["merge-base", base, head])
            .current_dir(root)
            .output()
            .context("git merge-base")?;
        if !mb.status.success() {
            bail!(
                "git merge-base failed: {}",
                String::from_utf8_lossy(&mb.stderr)
            );
        }
        let base_sha = String::from_utf8_lossy(&mb.stdout).trim().to_string();
        format!("{base_sha}..{head}")
    };
    let out = Command::new("git")
        .args(["diff", "--no-renames", "--name-only", "-z", &range])
        .current_dir(root)
        .output()
        .context("git diff --name-only")?;
    if !out.status.success() {
        bail!("git diff failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Scan the tree for `kernel_test_in!("<tag>", …)` (and `kernel_test!` ⇒
/// `verification`) and attribute each tag to its owning crate. This is the
/// zero-maintenance crate→subsystem map: it reads the same call sites the
/// kernel test registry does.
fn scan_test_tags(root: &Path, crates: &[CrateInfo]) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in crates {
        let dir = root.join(&c.dir);
        let mut tags: BTreeSet<String> = BTreeSet::new();
        collect_tags_in_dir(&dir, crates, &c.dir, &mut tags)?;
        if !tags.is_empty() {
            map.entry(c.name.clone()).or_default().extend(tags);
        }
    }
    Ok(map)
}

/// Walk `.rs` files under `dir`, but do not descend into a nested crate's
/// directory (those tags belong to the nested crate, matched separately).
fn collect_tags_in_dir(
    dir: &Path,
    crates: &[CrateInfo],
    owner_dir: &str,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("scan {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            // Do not descend into a nested crate's directory — its tags
            // belong to that crate and are collected on its own pass.
            if is_other_crate_dir(&path, crates, owner_dir) {
                continue;
            }
            collect_tags_in_dir(&path, crates, owner_dir, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let text = std::fs::read_to_string(&path)?;
            extract_tags(&text, out).with_context(|| format!("scan {}", path.display()))?;
        }
    }
    Ok(())
}

/// True if `path` is the root directory of a workspace crate other than the
/// one whose dir is `owner_dir` (so recursion stops at nested-crate roots).
fn is_other_crate_dir(path: &Path, crates: &[CrateInfo], owner_dir: &str) -> bool {
    crates
        .iter()
        .any(|c| c.dir != owner_dir && path.ends_with(&c.dir) && path.join("Cargo.toml").is_file())
}

/// Scan Rust tokens, including registrations nested in macro bodies. Comments
/// and string literals are opaque; raw strings and every macro delimiter work.
fn extract_tags(text: &str, out: &mut BTreeSet<String>) -> Result<()> {
    use proc_macro2::{TokenStream, TokenTree};
    fn visit(tokens: TokenStream, out: &mut BTreeSet<String>) -> Result<()> {
        let tokens: Vec<_> = tokens.into_iter().collect();
        for (i, token) in tokens.iter().enumerate() {
            if let TokenTree::Ident(name) = token {
                if let (Some(TokenTree::Punct(bang)), Some(TokenTree::Group(args))) =
                    (tokens.get(i + 1), tokens.get(i + 2))
                {
                    if bang.as_char() == '!' {
                        if name == "kernel_test" {
                            out.insert("verification".into());
                        } else if name == "kernel_test_in" {
                            if let Some(TokenTree::Literal(literal)) =
                                args.stream().into_iter().next()
                            {
                                let literal = literal.to_string();
                                let tag: String = if literal.starts_with('r') {
                                    let start = literal.find('"').context("raw tag start")? + 1;
                                    let end = literal.rfind('"').context("raw tag end")?;
                                    literal[start..end].into()
                                } else {
                                    serde_json::from_str(&literal)
                                        .context("kernel-test tag literal")?
                                };
                                crate::validate_test_subsystems(&tag)?;
                                out.insert(tag);
                            }
                        }
                    }
                }
            }
            if let TokenTree::Group(group) = token {
                visit(group.stream(), out)?;
            }
        }
        Ok(())
    }
    let tokens = text
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid Rust source: {e}"))?;
    visit(tokens, out)
}

/// One schema for human-readable JSON and Actions outputs.
fn plan_value(p: &Plan) -> serde_json::Value {
    serde_json::json!({
        "full": p.full, "reasons": p.reasons, "jobs": p.jobs(),
        "crates": p.crates, "changed_crates": p.changed_crates,
        "clippy_crates": p.clippy_crates, "host_clippy_crates": p.host_clippy_crates,
        "subsystems": p.subsystems, "clippy_arches": p.clippy_arches,
        "run_clippy": p.run_clippy, "run_boot_smoke": p.run_boot_smoke,
        "run_kernel_test": p.run_kernel_test, "run_musl_demo": p.run_musl_demo,
        "run_net_smoke": p.run_net_smoke, "run_feature_matrix": p.run_feature_matrix,
        "run_uefi": p.run_uefi, "run_large_memory": p.run_large_memory,
        "run_xapic": p.run_xapic, "run_virtio_mmio": p.run_virtio_mmio,
        "run_user_mode": p.run_user_mode,
    })
}

fn plan_to_json(p: &Plan) -> String {
    serde_json::to_string_pretty(&plan_value(p)).expect("serializable plan")
}

fn plan_to_github(p: &Plan) -> String {
    let mut fields = plan_value(p);
    fields["subsystems"] = p
        .subsystems
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",")
        .into();
    fields["jobs"] = p.jobs().join(" ").into();
    fields
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| {
            format!(
                "{k}={}\n",
                v.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string())
            )
        })
        .collect()
}

/// `cargo xtask affected` entry point.
pub fn affected_cmd(args: &AffectedArgs, root: &Path) -> Result<()> {
    let crates = load_workspace(root)?;
    let (tag_map, scan_failed) = match scan_test_tags(root, &crates) {
        Ok(tags) => (tags, false),
        Err(e) => {
            eprintln!("xtask affected: test inventory failed ({e:#}); using full matrix");
            (BTreeMap::new(), true)
        }
    };

    let event = args
        .event
        .clone()
        .or_else(|| std::env::var("GITHUB_EVENT_NAME").ok())
        .unwrap_or_else(|| "pull_request".to_string());

    let (changed, diff_failed) = if !args.changed_files.is_empty() {
        (args.changed_files.clone(), false)
    } else {
        match git_changed_files(root, &args.base, &args.head, &event) {
            Ok(f) => (f, false),
            Err(e) => {
                eprintln!("xtask affected: git diff failed ({e}); defaulting to a full run");
                (Vec::new(), true)
            }
        }
    };

    let force_full = args.force_full || diff_failed || scan_failed;
    let p = plan(&changed, &crates, &tag_map, &event, force_full);

    let github = args.github || matches!(args.format, OutputFormat::Github);
    if github {
        let text = plan_to_github(&p);
        if let Ok(path) = std::env::var("GITHUB_OUTPUT") {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .with_context(|| format!("opening GITHUB_OUTPUT at {path}"))?;
            f.write_all(text.as_bytes())?;
        }
        print!("{text}");
    } else {
        println!("{}", plan_to_json(&p));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ci(name: &str, dir: &str, deps: &[&str]) -> CrateInfo {
        CrateInfo {
            name: name.into(),
            dir: dir.into(),
            deps: deps.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// A small fixture graph:
    ///   lib  <- memory <- filesystem <- userspace <- frame
    ///   lib  <- net <- frame
    ///   frame, verification depend on ~everything.
    fn fixture() -> Vec<CrateInfo> {
        vec![
            ci("narf-lib", "lib", &[]),
            ci("narf-memory", "memory", &["narf-lib"]),
            ci(
                "narf-filesystem",
                "filesystem",
                &["narf-lib", "narf-memory"],
            ),
            ci("narf-userspace", "userspace", &["narf-filesystem"]),
            ci("narf-net", "net", &["narf-lib"]),
            ci("narf-drivers-net", "drivers/net", &["narf-net"]),
            ci("narf-drivers-gpu", "drivers/gpu", &["narf-lib"]),
            ci(
                "narf-frame",
                "frame",
                &[
                    "narf-userspace",
                    "narf-net",
                    "narf-drivers-gpu",
                    "narf-memory",
                ],
            ),
            ci(
                "narf-verification",
                "verification",
                &["narf-userspace", "narf-net", "narf-drivers-gpu"],
            ),
        ]
    }

    fn tags() -> BTreeMap<String, BTreeSet<String>> {
        let mut m = BTreeMap::new();
        let mut fs = BTreeSet::new();
        fs.insert("filesystem".to_string());
        fs.insert("filesystem/page_cache".to_string());
        m.insert("narf-filesystem".to_string(), fs);
        let mut us = BTreeSet::new();
        us.insert("syscall_abi".to_string());
        m.insert("narf-userspace".to_string(), us);
        let mut gpu = BTreeSet::new();
        gpu.insert("drivers/gpu".to_string());
        m.insert("narf-drivers-gpu".to_string(), gpu);
        m
    }

    #[test]
    fn file_maps_to_longest_prefix_crate() {
        let cr = fixture();
        assert_eq!(
            file_to_crate("drivers/net/src/lib.rs", &cr),
            Some("narf-drivers-net")
        );
        assert_eq!(
            file_to_crate("filesystem/src/page_cache.rs", &cr),
            Some("narf-filesystem")
        );
        assert_eq!(file_to_crate("README.md", &cr), None);
    }

    #[test]
    fn closure_pulls_in_reverse_dependents() {
        let cr = fixture();
        let mut seeds = BTreeSet::new();
        seeds.insert("narf-filesystem".to_string());
        let c = reverse_closure(&seeds, &cr);
        assert!(c.contains("narf-filesystem"));
        assert!(c.contains("narf-userspace"), "userspace depends on fs");
        assert!(c.contains("narf-frame"));
        assert!(c.contains("narf-verification"));
        assert!(!c.contains("narf-net"), "net does not depend on fs");
    }

    #[test]
    fn filesystem_change_runs_musl_not_net() {
        let cr = fixture();
        let p = plan(
            &["filesystem/src/page_cache.rs".to_string()],
            &cr,
            &tags(),
            "pull_request",
            false,
        );
        assert!(!p.full);
        assert!(p.run_boot_smoke && p.run_kernel_test);
        assert!(p.run_musl_demo, "fs → userspace path → musl");
        assert!(!p.run_net_smoke, "fs change must skip net-smoke");
        assert!(!p.run_feature_matrix, "no Cargo.toml touched");
        // Subsystem filter carries fs + userspace tags; `filesystem`
        // subsumes `filesystem/page_cache`.
        assert!(p.subsystems.contains("filesystem"));
        assert!(!p.subsystems.contains("filesystem/page_cache"));
        assert!(p.subsystems.contains("syscall_abi"));
        // Kernel linting retains both architectures for every package.
        assert_eq!(
            p.clippy_arches,
            vec!["x86_64".to_string(), "aarch64".to_string()]
        );
    }

    #[test]
    fn gpu_change_skips_net_and_musl() {
        let cr = fixture();
        let p = plan(
            &["drivers/gpu/src/lib.rs".to_string()],
            &cr,
            &tags(),
            "pull_request",
            false,
        );
        assert!(!p.full);
        assert!(p.run_boot_smoke && p.run_kernel_test);
        assert!(!p.run_musl_demo, "gpu change must skip musl-demo");
        assert!(!p.run_net_smoke, "gpu change must skip net-smoke");
        assert!(p.subsystems.contains("drivers"));
        // Both kernel architectures remain covered.
        assert_eq!(
            p.clippy_arches,
            vec!["x86_64".to_string(), "aarch64".to_string()]
        );
    }

    #[test]
    fn userspace_change_lints_both_kernel_arches() {
        let cr = fixture();
        let p = plan(
            &["userspace/src/syscall.rs".to_string()],
            &cr,
            &tags(),
            "pull_request",
            false,
        );
        assert!(!p.full);
        assert!(p.run_clippy);
        assert_eq!(
            p.clippy_arches,
            vec!["x86_64".to_string(), "aarch64".to_string()]
        );
    }

    #[test]
    fn hub_crate_forces_full() {
        let cr = fixture();
        let p = plan(
            &["lib/src/x.rs".to_string()],
            &cr,
            &tags(),
            "pull_request",
            false,
        );
        assert!(p.full);
        assert!(p.run_musl_demo && p.run_net_smoke && p.run_feature_matrix);
        assert!(p.subsystems.is_empty(), "full run has no subsystem filter");
    }

    #[test]
    fn infra_path_forces_full() {
        let cr = fixture();
        for f in [
            "Cargo.lock",
            ".github/workflows/ci.yml",
            "build/xtask/src/main.rs",
            "rust-toolchain.toml",
        ] {
            let p = plan(&[f.to_string()], &cr, &tags(), "pull_request", false);
            assert!(p.full, "{f} must force full");
        }
    }

    #[test]
    fn unmapped_path_forces_full_but_docs_do_not() {
        let cr = fixture();
        let p = plan(
            &["some_new_toplevel_thing/x.rs".to_string()],
            &cr,
            &tags(),
            "pull_request",
            false,
        );
        assert!(p.full, "unknown non-doc path is conservatively full");

        let docs = plan(
            &["docs/design.md".to_string(), "README.md".to_string()],
            &cr,
            &tags(),
            "pull_request",
            false,
        );
        assert!(!docs.full, "doc-only change is not full");
        assert!(!docs.run_boot_smoke && !docs.run_musl_demo && !docs.run_net_smoke);
        assert!(!docs.run_clippy, "doc-only change skips clippy");
    }

    #[test]
    fn push_event_uses_changed_crates() {
        let cr = fixture();
        let p = plan(
            &["filesystem/src/page_cache.rs".to_string()],
            &cr,
            &tags(),
            "push",
            false,
        );
        assert!(!p.full, "push-to-main diffs against the event before SHA");
    }

    #[test]
    fn cargo_toml_change_runs_feature_matrix() {
        let cr = fixture();
        let p = plan(
            &["userspace/Cargo.toml".to_string()],
            &cr,
            &tags(),
            "pull_request",
            false,
        );
        assert!(!p.full);
        assert!(p.run_feature_matrix, "member Cargo.toml ⇒ feature-matrix");
    }

    #[test]
    fn net_change_runs_net_smoke() {
        let cr = fixture();
        let p = plan(
            &["drivers/net/src/rx.rs".to_string()],
            &cr,
            &tags(),
            "pull_request",
            false,
        );
        assert!(!p.full);
        assert!(p.run_net_smoke);
        assert!(!p.run_musl_demo, "net driver change need not run musl");
    }

    #[test]
    fn oversized_subsystem_filter_falls_back_to_full_suite() {
        let cr = fixture();
        // Give filesystem more tags than the cap so the filter is dropped.
        let mut tm = tags();
        let mut many = BTreeSet::new();
        for i in 0..MAX_SUBSYSTEM_FILTER_BYTES / 10 {
            many.insert(format!("subsystem{i}"));
        }
        tm.insert("narf-filesystem".to_string(), many);
        let p = plan(
            &["filesystem/src/x.rs".to_string()],
            &cr,
            &tm,
            "pull_request",
            false,
        );
        assert!(!p.full, "still a scoped run, just no subsystem filter");
        assert!(p.run_kernel_test);
        assert!(
            p.subsystems.is_empty(),
            "oversized filter dropped ⇒ run the whole suite"
        );
    }

    #[test]
    fn extract_tags_handles_multiline_and_bare() {
        let src = r#"
            kernel_test_in!(
                "filesystem/page_cache",
                smoke_x
            );
            kernel_test_in!("memory", smoke_y);
            kernel_test!(smoke_z);
        "#;
        let mut out = BTreeSet::new();
        extract_tags(src, &mut out).unwrap();
        assert!(out.contains("filesystem/page_cache"));
        assert!(out.contains("memory"));
        assert!(out.contains("verification"));
    }
    fn strings(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn lint_only_direct_changes_even_when_tests_are_full() {
        for (file, package) in [
            ("filesystem/src/lib.rs", "narf-filesystem"),
            ("lib/src/lib.rs", "narf-lib"),
        ] {
            let p = plan(&[file.into()], &fixture(), &tags(), "pull_request", false);
            assert_eq!(p.clippy_crates, strings(&[package]));
            assert_eq!(p.changed_crates, strings(&[package]));
            assert!(p.crates.contains("narf-frame"));
        }
    }

    #[test]
    fn scoped_shards_follow_dependencies_not_kernel_linkage() {
        let p = plan(
            &["drivers/gpu/src/lib.rs".into()],
            &fixture(),
            &tags(),
            "pull_request",
            false,
        );
        assert!(p.run_kernel_test);
        assert!(!p.run_large_memory && !p.run_xapic && !p.run_virtio_mmio && !p.run_user_mode);
        let p = plan(
            &["filesystem/src/lib.rs".into()],
            &fixture(),
            &tags(),
            "pull_request",
            false,
        );
        assert!(p.run_user_mode);
        assert!(!p.run_large_memory && !p.run_xapic && !p.run_virtio_mmio);
    }

    #[test]
    fn full_matrix_escape_hatches() {
        for event in ["schedule", "workflow_dispatch"] {
            let p = plan(&["README.md".into()], &fixture(), &tags(), event, false);
            assert!(
                p.full && p.run_large_memory && p.run_xapic && p.run_user_mode && p.run_virtio_mmio
            );
            assert_eq!(p.clippy_crates.len(), fixture().len());
        }
        let p = plan(&[], &fixture(), &tags(), "pull_request", false);
        assert!(p.full);
        let p = plan(
            &["README.md".into()],
            &fixture(),
            &tags(),
            "pull_request",
            true,
        );
        assert!(p.full);
    }

    #[test]
    fn embedded_images_select_consumer_without_linting_enclosing_crate() {
        for path in [
            "userspace/shell/src/main.rs",
            "userspace/login-core/src/lib.rs",
            "narf-libc/src/lib.rs",
        ] {
            let p = plan(&[path.into()], &fixture(), &tags(), "pull_request", false);
            assert!(!p.full, "{path}");
            assert!(p.crates.contains(VERIFICATION));
            assert!(p.run_kernel_test && p.run_musl_demo && p.run_user_mode);
            assert!(p.clippy_crates.is_empty());
        }
    }

    #[test]
    fn runtime_build_script_edge_is_not_a_lint_target() {
        let mut crates = fixture();
        crates.push(ci("narf-user-runtime", "user-runtime", &[]));
        let p = plan(
            &["user-runtime/src/lib.rs".into()],
            &crates,
            &tags(),
            "pull_request",
            false,
        );
        assert!(p.crates.contains(VERIFICATION));
        assert_eq!(p.clippy_crates, strings(&["narf-user-runtime"]));
        assert!(p.run_musl_demo);
    }

    #[test]
    fn assets_are_build_inputs_and_deleted_manifests_force_full() {
        for path in ["filesystem/fixture.txt", "drivers/gpu/cursor.png"] {
            let p = plan(&[path.into()], &fixture(), &tags(), "pull_request", false);
            assert!(p.run_kernel_test && p.run_clippy);
        }
        let p = plan(
            &["drivers/gpu/deleted/Cargo.toml".into()],
            &fixture(),
            &tags(),
            "pull_request",
            false,
        );
        assert!(p.full);
    }

    #[test]
    fn host_and_loader_changes_have_separate_lint_gates() {
        let mut crates = fixture();
        crates.push(ci("xtask", "build/xtask", &[]));
        crates.push(ci("cargo-narf", "build/cargo-narf", &[]));
        let p = plan(
            &["build/xtask/src/main.rs".into()],
            &crates,
            &tags(),
            "pull_request",
            false,
        );
        assert!(p.full);
        assert_eq!(p.host_clippy_crates, strings(&["xtask"]));
        assert!(p.clippy_crates.is_empty());
        let p = plan(
            &["build/uefi-loader/src/main.rs".into()],
            &crates,
            &tags(),
            "pull_request",
            false,
        );
        assert!(p.run_uefi && !p.full && !p.run_clippy);
    }

    #[test]
    fn compact_prefixes_preserve_exact_test_membership() {
        let selected = strings(&["drivers/usb/hid", "drivers/usb/uac", "audio/hda"]);
        let universe = strings(&[
            "drivers/usb/hid",
            "drivers/usb/uac",
            "audio/hda",
            "audio/sbc",
            "drivers/gpu",
        ]);
        let compact = compact_tags(selected.clone(), &universe);
        assert_eq!(compact, strings(&["drivers/usb", "audio/hda"]));
        for tag in universe {
            assert_eq!(
                selected.contains(&tag),
                compact
                    .iter()
                    .any(|t| tag == *t || tag.starts_with(&format!("{t}/")))
            );
        }
    }

    #[test]
    fn many_child_tags_fit_without_disabling_test_selection() {
        let cr = fixture();
        let mut tm = tags();
        tm.insert(
            "narf-filesystem".into(),
            (0..100).map(|i| format!("filesystem/area{i}")).collect(),
        );
        let p = plan(
            &["filesystem/src/lib.rs".into()],
            &cr,
            &tm,
            "pull_request",
            false,
        );
        assert!(p.subsystems.contains("filesystem"));
        assert!(!p.full && !p.subsystems.is_empty());
    }

    #[test]
    fn registration_scan_ignores_examples_and_accepts_rust_macro_syntax() {
        let mut out = BTreeSet::new();
        extract_tags(
            r##"
            // kernel_test_in!("wrong/comment", test);
            /// kernel_test!(wrong);
            const EXAMPLE: &str = "kernel_test_in!(\"wrong/string\", test)";
            kernel_test_in ! { r#"audio/hda"#, test }
            fn nested() { narf_kernel_test::kernel_test_in!["filesystem", test]; }
            macro_rules! register { () => { kernel_test_in!("drivers/usb", test); } }
        "##,
            &mut out,
        )
        .unwrap();
        assert_eq!(out, strings(&["audio/hda", "filesystem", "drivers/usb"]));
        assert!(extract_tags("fn broken(", &mut out).is_err());
    }

    #[test]
    fn github_outputs_are_consistent_json() {
        let p = plan(
            &["filesystem/src/lib.rs".into()],
            &fixture(),
            &tags(),
            "pull_request",
            false,
        );
        let json: serde_json::Value = serde_json::from_str(&plan_to_json(&p)).unwrap();
        let github = plan_to_github(&p);
        let outputs: BTreeMap<_, _> = github.lines().filter_map(|l| l.split_once('=')).collect();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(outputs["clippy_crates"]).unwrap(),
            json["clippy_crates"]
        );
        assert_eq!(outputs["run_user_mode"], "true");
        assert_eq!(outputs["subsystems"], "filesystem,syscall_abi");
    }
    #[test]
    fn metadata_keeps_renamed_optional_build_and_target_edges() {
        let metadata = serde_json::json!({
            "workspace_root": "/workspace",
            "workspace_members": ["root", "child", "leaf"],
            "packages": [
                {"id": "root", "name": "root", "manifest_path": "/workspace/Cargo.toml",
                 "dependencies": [
                    {"name": "child", "rename": "renamed", "path": "/workspace/nested", "kind": "build", "optional": true, "target": "cfg(target_arch = \"aarch64\")"},
                    {"name": "external", "path": null}
                 ]},
                {"id": "child", "name": "child", "manifest_path": "/workspace/nested/Cargo.toml",
                 "dependencies": [{"name": "leaf", "path": "/workspace/nested/leaf", "kind": "dev"}]},
                {"id": "leaf", "name": "leaf", "manifest_path": "/workspace/nested/leaf/Cargo.toml", "dependencies": []},
                {"id": "external", "name": "external", "manifest_path": "/external/Cargo.toml"}
            ]
        });
        let crates = workspace_crates(&metadata).unwrap();
        assert_eq!(file_to_crate("src/lib.rs", &crates), Some("root"));
        assert_eq!(
            file_to_crate("nested/leaf/src/lib.rs", &crates),
            Some("leaf")
        );
        assert_eq!(
            file_to_crate("nested-extra/src/lib.rs", &crates),
            Some("root")
        );
        assert_eq!(
            reverse_closure(&strings(&["leaf"]), &crates),
            strings(&["root", "child", "leaf"])
        );
        assert!(!crates[0].deps.contains(&"external".into()));
    }
}
