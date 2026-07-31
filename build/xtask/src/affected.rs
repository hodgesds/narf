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
//!    path, or when the CI event is a push-to-main / nightly / manual run.
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
        || base.ends_with(".txt")
        || base.ends_with(".png")
        || base.ends_with(".jpg")
        || base.ends_with(".svg")
}

/// A path that is neither infra nor mapped to a crate but must still force
/// a full run only if it isn't ignorable. Split out for the unit tests.
fn is_arch_sensitive(rel: &str) -> bool {
    rel.starts_with("arch/")
        || rel.starts_with("drivers/")
        || rel.contains("aarch64")
        || rel.ends_with(".S")
        || rel.ends_with(".s")
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
    /// Base git ref to diff against. The diff uses the merge-base of this
    /// ref with `--head`, so a stale base branch does not over-report.
    #[arg(long, default_value = "origin/main")]
    base: String,

    /// The current side of the diff.
    #[arg(long, default_value = "HEAD")]
    head: String,

    /// CI event name. Defaults to `$GITHUB_EVENT_NAME`, else
    /// `pull_request`. `push`/`schedule`/`workflow_dispatch` force a full
    /// run (post-merge + nightly always run the complete matrix).
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
        if c.dir.is_empty() {
            continue;
        }
        let under = rel == c.dir || rel.starts_with(&format!("{}/", c.dir));
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
    if matches!(event, "push" | "schedule" | "workflow_dispatch") {
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
    let mut cargo_toml_touched = false;
    let mut arch_sensitive = false;
    let mut any_code = false;
    for f in changed_files {
        let base = f.rsplit('/').next().unwrap_or(f);
        if base == "Cargo.toml" && f != "Cargo.toml" {
            cargo_toml_touched = true;
        }
        if is_arch_sensitive(f) {
            arch_sensitive = true;
        }
        if is_infra_path(f) {
            p.full = true;
            p.reasons.push(format!("infra path `{f}`"));
            any_code = true;
            continue;
        }
        if is_ignorable_path(f) {
            continue;
        }
        match file_to_crate(f, crates) {
            Some(name) => {
                any_code = true;
                seeds.insert(name.to_string());
            }
            None => {
                // Unrecognized, non-doc path: be safe.
                p.full = true;
                p.reasons.push(format!("unmapped path `{f}` ⇒ full"));
                any_code = true;
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

    let closure = reverse_closure(&seeds, crates);
    let has = |n: &str| closure.contains(n);
    let has_any = |set: &[&str]| set.iter().any(|n| closure.contains(*n));

    if p.full {
        // Full: report the whole picture but let the workflow run all jobs.
        p.crates = crates.iter().map(|c| c.name.clone()).collect();
        p.run_clippy = true;
        p.clippy_arches = vec!["x86_64".into(), "aarch64".into()];
        p.run_boot_smoke = true;
        p.run_kernel_test = true;
        p.run_musl_demo = true;
        p.run_net_smoke = true;
        p.run_feature_matrix = true;
        // No subsystem filter on a full run (execute every kernel test).
        return p;
    }

    p.crates = closure.clone();

    // clippy is the compile gate: run it for any code change. Prune the
    // aarch64 arch unless an arch-sensitive file was touched.
    p.run_clippy = any_code;
    p.clippy_arches = if arch_sensitive {
        vec!["x86_64".into(), "aarch64".into()]
    } else {
        vec!["x86_64".into()]
    };

    // Boot-based gates: only when a real kernel crate is in the closure
    // (frame links ~everything, so frame ∈ closure ⟺ a kernel crate
    // changed; xtask/doc-only changes never pull it in).
    p.run_boot_smoke = has(KERNEL_BIN);
    p.run_kernel_test = has(KERNEL_BIN) || has(VERIFICATION);

    // musl-demo: linux-compat userspace execution path, plus the C libc
    // dir (not a cargo member, so keyed by path).
    let libc_touched = changed_files.iter().any(|f| f.starts_with("narf-libc/"));
    p.run_musl_demo = has_any(MUSL_CRATES) || libc_touched;

    // net-smoke: off-box networking path.
    p.run_net_smoke = has_any(NET_CRATES);

    // feature-matrix: feature forwarding lives in member Cargo.toml files.
    p.run_feature_matrix = cargo_toml_touched;

    // Kernel-test subsystem filter: the tags owned by the affected crates.
    // A very broad closure (e.g. a change to a widely-depended-on crate
    // like the VFS, which ~20 driver crates use for devfs/sysfs) would
    // produce a filter of hundreds of tags — long enough to overflow the
    // kernel cmdline and pointless besides. Above the cap, drop the filter
    // and run the whole suite (a safe superset of the intended set).
    if p.run_kernel_test {
        let mut tags: BTreeSet<String> = BTreeSet::new();
        for c in &closure {
            if let Some(t) = tag_map.get(c) {
                tags.extend(t.iter().cloned());
            }
        }
        let collapsed = collapse_tags(tags);
        if collapsed.len() > MAX_SUBSYSTEM_FILTER {
            p.reasons.push(format!(
                "{} affected subsystems > cap {} — running the full kernel-test suite",
                collapsed.len(),
                MAX_SUBSYSTEM_FILTER
            ));
        } else {
            p.subsystems = collapsed;
        }
    }

    p
}

/// Beyond this many distinct subsystem tags, the kernel-test filter is
/// dropped (run everything) rather than passed as an unwieldy — and
/// possibly cmdline-overflowing — `test_subsystem=` list.
const MAX_SUBSYSTEM_FILTER: usize = 32;

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
        let dir = manifest
            .strip_suffix("/Cargo.toml")
            .unwrap_or(manifest)
            .strip_prefix(&format!("{ws_root}/"))
            .unwrap_or(manifest)
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
fn git_changed_files(root: &Path, base: &str, head: &str) -> Result<Vec<String>> {
    // Resolve the merge-base; if it fails (shallow clone missing the base),
    // the caller falls back to a full run.
    let mb = Command::new("git")
        .args(["merge-base", base, head])
        .current_dir(root)
        .output()
        .context("git merge-base")?;
    let range = if mb.status.success() {
        let base_sha = String::from_utf8_lossy(&mb.stdout).trim().to_string();
        format!("{base_sha}...{head}")
    } else {
        // No common ancestor found — diff against the base ref directly.
        format!("{base}...{head}")
    };
    let out = Command::new("git")
        .args(["diff", "--name-only", &range])
        .current_dir(root)
        .output()
        .context("git diff --name-only")?;
    if !out.status.success() {
        bail!("git diff failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Scan the tree for `kernel_test_in!("<tag>", …)` (and `kernel_test!` ⇒
/// `verification`) and attribute each tag to its owning crate. This is the
/// zero-maintenance crate→subsystem map: it reads the same call sites the
/// kernel test registry does.
fn scan_test_tags(root: &Path, crates: &[CrateInfo]) -> BTreeMap<String, BTreeSet<String>> {
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in crates {
        let dir = root.join(&c.dir);
        let mut tags: BTreeSet<String> = BTreeSet::new();
        collect_tags_in_dir(&dir, crates, &c.dir, &mut tags);
        if !tags.is_empty() {
            map.entry(c.name.clone()).or_default().extend(tags);
        }
    }
    map
}

/// Walk `.rs` files under `dir`, but do not descend into a nested crate's
/// directory (those tags belong to the nested crate, matched separately).
fn collect_tags_in_dir(
    dir: &Path,
    crates: &[CrateInfo],
    owner_dir: &str,
    out: &mut BTreeSet<String>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
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
            collect_tags_in_dir(&path, crates, owner_dir, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(text) = std::fs::read_to_string(&path) {
                extract_tags(&text, out);
            }
        }
    }
}

/// True if `path` is the root directory of a workspace crate other than the
/// one whose dir is `owner_dir` (so recursion stops at nested-crate roots).
fn is_other_crate_dir(path: &Path, crates: &[CrateInfo], owner_dir: &str) -> bool {
    crates
        .iter()
        .any(|c| c.dir != owner_dir && path.ends_with(&c.dir) && path.join("Cargo.toml").is_file())
}

/// Pull every `kernel_test_in!("tag", …)` first-argument string literal,
/// plus a `verification` tag for any bare `kernel_test!(…)`.
///
/// Only an *invocation* counts: after the macro name there must be a `(`
/// (whitespace/newlines allowed) — this rejects the many prose mentions of
/// `kernel_test_in!` in doc comments, which would otherwise capture the
/// next unrelated string literal in the file.
fn extract_tags(text: &str, out: &mut BTreeSet<String>) {
    let bytes = text.as_bytes();
    // `kernel_test_in!(  "<tag>"` — the tag is the first string literal.
    let mut from = 0usize;
    while let Some(pos) = text[from..].find("kernel_test_in!") {
        let after = from + pos + "kernel_test_in!".len();
        from = after;
        // Require `(` (skipping whitespace) then `"` (skipping whitespace).
        let mut i = after;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'(' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'"' {
            continue;
        }
        i += 1;
        if let Some(q2) = text[i..].find('"') {
            out.insert(text[i..i + q2].to_string());
        }
    }
    // Bare `kernel_test!(…)` ⇒ the implicit `verification` subsystem.
    let mut from = 0usize;
    while let Some(pos) = text[from..].find("kernel_test!") {
        let after = from + pos + "kernel_test!".len();
        from = after;
        let mut i = after;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'(' {
            out.insert("verification".to_string());
        }
    }
}

/// Serialize a plan to compact JSON without pulling in serde derive.
fn plan_to_json(p: &Plan) -> String {
    let arr = |v: &BTreeSet<String>| {
        let items: Vec<String> = v.iter().map(|s| format!("{s:?}")).collect();
        format!("[{}]", items.join(","))
    };
    let arr_vec = |v: &[String]| {
        let items: Vec<String> = v.iter().map(|s| format!("{s:?}")).collect();
        format!("[{}]", items.join(","))
    };
    let jobs = p.jobs();
    format!(
        "{{\n  \"full\": {},\n  \"reasons\": {},\n  \"jobs\": {},\n  \"crates\": {},\n  \"subsystems\": {},\n  \"clippy_arches\": {},\n  \"run_clippy\": {},\n  \"run_boot_smoke\": {},\n  \"run_kernel_test\": {},\n  \"run_musl_demo\": {},\n  \"run_net_smoke\": {},\n  \"run_feature_matrix\": {}\n}}",
        p.full,
        arr_vec(&p.reasons),
        arr_vec(&jobs),
        arr(&p.crates),
        arr(&p.subsystems),
        arr_vec(&p.clippy_arches),
        p.run_clippy,
        p.run_boot_smoke,
        p.run_kernel_test,
        p.run_musl_demo,
        p.run_net_smoke,
        p.run_feature_matrix,
    )
}

/// Serialize to GitHub Actions `name=value` output lines.
fn plan_to_github(p: &Plan) -> String {
    let json_arr = |v: &[String]| {
        let items: Vec<String> = v.iter().map(|s| format!("{s:?}")).collect();
        format!("[{}]", items.join(","))
    };
    let jobs = p.jobs().join(" ");
    let subs = p.subsystems.iter().cloned().collect::<Vec<_>>().join(",");
    format!(
        "full={}\njobs={}\nsubsystems={}\nclippy_arches={}\nrun_clippy={}\nrun_boot_smoke={}\nrun_kernel_test={}\nrun_musl_demo={}\nrun_net_smoke={}\nrun_feature_matrix={}\n",
        p.full,
        jobs,
        subs,
        json_arr(&p.clippy_arches),
        p.run_clippy,
        p.run_boot_smoke,
        p.run_kernel_test,
        p.run_musl_demo,
        p.run_net_smoke,
        p.run_feature_matrix,
    )
}

/// `cargo xtask affected` entry point.
pub fn affected_cmd(args: &AffectedArgs, root: &Path) -> Result<()> {
    let crates = load_workspace(root)?;
    let tag_map = scan_test_tags(root, &crates);

    let event = args
        .event
        .clone()
        .or_else(|| std::env::var("GITHUB_EVENT_NAME").ok())
        .unwrap_or_else(|| "pull_request".to_string());

    let (changed, diff_failed) = if !args.changed_files.is_empty() {
        (args.changed_files.clone(), false)
    } else {
        match git_changed_files(root, &args.base, &args.head) {
            Ok(f) => (f, false),
            Err(e) => {
                eprintln!("xtask affected: git diff failed ({e}); defaulting to a full run");
                (Vec::new(), true)
            }
        }
    };

    let force_full = args.force_full || diff_failed;
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
        // Only x86_64 clippy (no arch-sensitive file).
        assert_eq!(p.clippy_arches, vec!["x86_64".to_string()]);
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
        assert!(p.subsystems.contains("drivers/gpu"));
        // drivers/ is arch-sensitive ⇒ both clippy arches.
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
    fn push_event_forces_full() {
        let cr = fixture();
        let p = plan(
            &["filesystem/src/page_cache.rs".to_string()],
            &cr,
            &tags(),
            "push",
            false,
        );
        assert!(p.full, "push-to-main always runs the full matrix");
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
        for i in 0..MAX_SUBSYSTEM_FILTER + 5 {
            many.insert(format!("filesystem/area{i}"));
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
        extract_tags(src, &mut out);
        assert!(out.contains("filesystem/page_cache"));
        assert!(out.contains("memory"));
        assert!(out.contains("verification"));
    }
}
