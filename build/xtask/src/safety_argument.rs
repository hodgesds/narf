//! `cargo xtask check-safety-argument` — the CI check the process doc
//! promises (SEC-B9, #1284).
//!
//! `process/specification/spec.md` §6.3 says of `safety-argument.toml`:
//! "CI verifies the references exist", and that "a linter run by CI parses
//! the file, verifies each `ref` resolves to a present line, and counts
//! unique invariants covered" — but no such checker existed in tree, so the
//! existence check itself was unverified. This module is that checker, and
//! it is wired into CI (`.github/workflows/ci.yml`, job `safety-argument`)
//! so it runs on every PR and every push to main.
//!
//! Rules (hard failures — any one exits nonzero):
//!
//! 1. The file parses as TOML and `[safety_argument] schema_version` is 2
//!    (schema v2: linkage fields, see the file header).
//! 2. Every `[[invariants_preserved]]` entry has a non-empty `ref` and
//!    `argument`.
//! 3. Every `ref` is `security-model/specification/spec.md#L<line>` where
//!    `<line>` is a present, non-empty line of that file at the commit being
//!    reviewed.
//! 4. No entry cites a retired line (currently L75 — the "file it as a bug"
//!    rule, which states a filing obligation, not an invariant a change
//!    preserves) unless it carries `retired_ref = true`, which grandfathers
//!    the 98 pre-retirement L75 citations pending re-citation.
//! 5. Linkage fields, when present, are well-formed and resolve: `pr` is a
//!    positive integer, `commit` is 7–40 hex chars, every `files` path
//!    exists in the tree, every `enforces` entry is `path::fn` where the
//!    file exists and contains `fn <name>` (textual check — it names the
//!    enforcement point, it does not prove the function enforces anything).
//! 6. With `--diff-base <ref>`, entries added or reworded since that base
//!    must carry all of `pr`, `commit`, `files`, and `enforces` — linkage is
//!    not optional for new claims. (CI passes the PR's merge-base.) The
//!    comparison is by entry content, not by diff line numbers: a pure
//!    insertion above the entries shifts every header line, and unified
//!    diffs align the repeated `[[invariants_preserved]]` headers
//!    arbitrarily across that shift, so line-based "added entry" detection
//!    reports pre-existing entries as new. Comparing (ref, argument)
//!    multisets between the base file and the current file is exact: an
//!    entry is new iff the base does not already contain that claim.
//!
//! Warnings (reported, exit code unaffected): entries with no linkage at
//! all (legacy entries that predate schema v2), `retired_ref = true` on a
//! live ref, and unknown per-entry keys. The checker also prints coverage
//! stats: total entries, unique refs, per-ref counts for the top refs, and
//! the retired-ref count — the "counts unique invariants covered" the
//! process doc asks for.
//!
//! This is file/CI metadata only — perf class (a). It changes no runtime
//! behaviour, no TCB code, and no kernel data path.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Path of the safety-argument file, relative to the workspace root.
pub const SAFETY_ARGUMENT_REL: &str = "safety-argument.toml";
/// Path of the spec the `ref`s point into, relative to the workspace root.
pub const SPEC_REL: &str = "security-model/specification/spec.md";
/// Schema version the checker accepts.
pub const SCHEMA_VERSION: i64 = 2;
/// Spec lines that are retired as citable invariants. L75 is the "anything
/// not listed above is a hole, and must be filed as a security bug" rule:
/// a filing obligation, not an invariant a change can preserve.
pub const RETIRED_LINES: &[u32] = &[75];

/// Args for `xtask check-safety-argument`.
#[derive(clap::Args)]
pub struct Args {
    /// Path to `safety-argument.toml` (default: `<root>/safety-argument.toml`).
    #[arg(long)]
    file: Option<PathBuf>,

    /// Require entries added in the diff against this git ref to carry all
    /// linkage fields (`pr`, `commit`, `files`, `enforces`). CI passes the
    /// PR's merge-base with origin/main. If the base cannot be resolved
    /// (shallow checkout, no git), the diff-mode check is skipped with a
    /// warning and the full-file check still runs.
    #[arg(long)]
    diff_base: Option<String>,
}

/// Outcome of a check: hard errors (fail the gate), warnings, and coverage
/// stats for the summary line.
#[derive(Default, Debug)]
pub struct CheckReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub total_entries: usize,
    pub unique_refs: usize,
    pub retired_entries: usize,
    pub entries_without_linkage: usize,
    pub ref_counts: BTreeMap<String, usize>,
}

/// Run the check against the workspace at `root`. Prints the report and
/// returns `Err` when any hard rule fails.
pub fn run(args: &Args, root: &Path) -> Result<()> {
    let file = args
        .file
        .clone()
        .unwrap_or_else(|| root.join(SAFETY_ARGUMENT_REL));
    let doc =
        std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
    let spec_path = root.join(SPEC_REL);
    let spec = std::fs::read_to_string(&spec_path)
        .with_context(|| format!("reading {}", spec_path.display()))?;

    let mut report = check_document(&doc, &spec, root);

    if let Some(base) = &args.diff_base {
        // The base comparison is advisory: a base that cannot be resolved
        // (e.g. a shallow local checkout) must not fail the gate. CI uses
        // fetch-depth 0, so this path should not trigger there.
        match base_document(root, base) {
            Ok(Some(base_doc)) => {
                enforce_new_entry_linkage(&doc, &base_doc, &mut report);
            }
            Ok(None) => {
                report.warnings.push(format!(
                    "diff-mode skipped: base `{base}` has no safety-argument.toml; \
                     new-entry linkage not enforced for this run"
                ));
            }
            Err(e) => {
                report.warnings.push(format!(
                    "diff-mode skipped: could not read base `{base}` ({e}); \
                     new-entry linkage not enforced for this run"
                ));
            }
        }
    }

    print_report(&file, &report);
    if !report.errors.is_empty() {
        bail!(
            "safety-argument check failed: {} error(s), {} warning(s)",
            report.errors.len(),
            report.warnings.len()
        );
    }
    Ok(())
}

/// Pure core: check one parsed document against the spec text. `root` is
/// used only to resolve `files` / `enforces` paths.
pub fn check_document(doc: &str, spec: &str, root: &Path) -> CheckReport {
    let mut report = CheckReport::default();
    let spec_lines: Vec<&str> = spec.lines().collect();

    let value: toml::Value = match doc.parse() {
        Ok(v) => v,
        Err(e) => {
            report
                .errors
                .push(format!("safety-argument.toml does not parse: {e}"));
            return report;
        }
    };
    let table = match value.as_table() {
        Some(t) => t,
        None => {
            report
                .errors
                .push("safety-argument.toml is not a TOML table".to_string());
            return report;
        }
    };

    let version = table
        .get("safety_argument")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("schema_version"))
        .and_then(|v| v.as_integer());
    match version {
        Some(SCHEMA_VERSION) => {}
        Some(other) => report.errors.push(format!(
            "[safety_argument] schema_version is {other}, expected {SCHEMA_VERSION}"
        )),
        None => report
            .errors
            .push("[safety_argument] schema_version is missing (expected 2)".to_string()),
    }

    let entries = match table.get("invariants_preserved").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => {
            report
                .errors
                .push("no [[invariants_preserved]] entries found".to_string());
            return report;
        }
    };
    if entries.is_empty() {
        report
            .errors
            .push("[[invariants_preserved]] is empty".to_string());
        return report;
    }
    report.total_entries = entries.len();

    for (idx, entry) in entries.iter().enumerate() {
        check_entry(idx, entry, &spec_lines, root, &mut report);
    }
    report.unique_refs = report.ref_counts.len();
    report
}

fn check_entry(
    idx: usize,
    entry: &toml::Value,
    spec_lines: &[&str],
    root: &Path,
    report: &mut CheckReport,
) {
    let n = idx + 1;
    let entry = match entry.as_table() {
        Some(t) => t,
        None => {
            report.errors.push(format!("entry {n}: not a TOML table"));
            return;
        }
    };

    // Unknown keys are a warning, not an error: the schema may grow, and a
    // typo'd key name must not silently pass as "no linkage".
    for key in entry.keys() {
        if !matches!(
            key.as_str(),
            "ref"
                | "argument"
                | "pr"
                | "commit"
                | "files"
                | "enforces"
                | "retired_ref"
                | "agent"
                | "prompt_hash"
        ) {
            report
                .warnings
                .push(format!("entry {n}: unknown key `{key}`"));
        }
    }

    let mut has_linkage = false;

    let ref_line = match entry.get("ref").and_then(|v| v.as_str()) {
        Some(r) if !r.is_empty() => r,
        _ => {
            report.errors.push(format!(
                "entry {n}: missing or empty `ref` (expected \
                 `security-model/specification/spec.md#L<line>`)"
            ));
            return;
        }
    };
    let line_no = match parse_ref(ref_line) {
        Some(l) => l,
        None => {
            report.errors.push(format!(
                "entry {n}: malformed `ref` `{ref_line}` (expected \
                 `security-model/specification/spec.md#L<line>`)"
            ));
            return;
        }
    };
    *report.ref_counts.entry(ref_line.to_string()).or_insert(0) += 1;
    match spec_lines.get((line_no as usize).saturating_sub(1)) {
        Some(text) if !text.trim().is_empty() => {}
        Some(_) => report.errors.push(format!(
            "entry {n}: `ref` {ref_line} points at an empty spec line"
        )),
        None => report.errors.push(format!(
            "entry {n}: `ref` {ref_line} is beyond the end of \
             security-model/specification/spec.md ({} lines)",
            spec_lines.len()
        )),
    }
    let retired_ref = entry
        .get("retired_ref")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if RETIRED_LINES.contains(&line_no) {
        report.retired_entries += 1;
        if !retired_ref {
            report.errors.push(format!(
                "entry {n}: cites retired line L{line_no} ({ref_line}); L{line_no} is a \
                 filing rule, not a citable invariant — re-cite to a genuine \
                 invariant, or mark the entry `retired_ref = true` if it is a \
                 grandfathered pre-retirement citation"
            ));
        }
    } else if retired_ref {
        report.warnings.push(format!(
            "entry {n}: `retired_ref = true` on a live ref ({ref_line}); the flag is stale"
        ));
    }

    match entry.get("argument").and_then(|v| v.as_str()) {
        Some(a) if !a.trim().is_empty() => {}
        _ => report
            .errors
            .push(format!("entry {n}: missing or empty `argument`")),
    }

    if let Some(pr) = entry.get("pr") {
        has_linkage = true;
        match pr.as_integer() {
            Some(p) if p > 0 => {}
            _ => report.errors.push(format!(
                "entry {n}: `pr` must be a positive integer, got `{pr}`"
            )),
        }
    }
    if let Some(commit) = entry.get("commit") {
        has_linkage = true;
        match commit.as_str() {
            Some(c) if is_hex_sha(c) => {}
            Some(c) => report.errors.push(format!(
                "entry {n}: `commit` must be 7–40 hex chars, got `{c}`"
            )),
            None => report.errors.push(format!(
                "entry {n}: `commit` must be a string, got `{commit}`"
            )),
        }
    }
    if let Some(files) = entry.get("files") {
        has_linkage = true;
        match files.as_array() {
            Some(list) if !list.is_empty() => {
                for f in list {
                    match f.as_str() {
                        Some(p) => check_repo_path(n, p, root, report),
                        None => report.errors.push(format!(
                            "entry {n}: `files` entries must be strings, got `{f}`"
                        )),
                    }
                }
            }
            _ => report.errors.push(format!(
                "entry {n}: `files` must be a non-empty array of paths"
            )),
        }
    }
    if let Some(enforces) = entry.get("enforces") {
        has_linkage = true;
        match enforces.as_array() {
            Some(list) if !list.is_empty() => {
                for e in list {
                    match e.as_str() {
                        Some(s) => check_enforces(n, s, root, report),
                        None => report.errors.push(format!(
                            "entry {n}: `enforces` entries must be strings, got `{e}`"
                        )),
                    }
                }
            }
            _ => report.errors.push(format!(
                "entry {n}: `enforces` must be a non-empty array of `path::fn`"
            )),
        }
    }

    if !has_linkage {
        report.entries_without_linkage += 1;
        report.warnings.push(format!(
            "entry {n}: no linkage (`pr`/`commit`/`files`/`enforces`); \
             pre-schema-v2 legacy entry, re-cite with linkage when touched"
        ));
    }
}

/// `security-model/specification/spec.md#L<line>` → the line number, else `None`.
fn parse_ref(r: &str) -> Option<u32> {
    let rest = r.strip_prefix("security-model/specification/spec.md#L")?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

fn is_hex_sha(s: &str) -> bool {
    (7..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn check_repo_path(n: usize, p: &str, root: &Path, report: &mut CheckReport) {
    let path = Path::new(p);
    if path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        report.errors.push(format!(
            "entry {n}: `files` path `{p}` must be repo-relative (no absolute path, no `..`)"
        ));
        return;
    }
    if !root.join(path).is_file() {
        report.errors.push(format!(
            "entry {n}: `files` path `{p}` does not exist in the tree"
        ));
    }
}

/// `path/to/file.rs::function` — the file must exist and textually contain
/// `fn <name>`. This names the enforcement point; it does not prove the
/// function enforces the claimed invariant (reviewers still read the prose).
fn check_enforces(n: usize, s: &str, root: &Path, report: &mut CheckReport) {
    let Some((path, name)) = s.rsplit_once("::") else {
        report.errors.push(format!(
            "entry {n}: `enforces` entry `{s}` must be `path/to/file.rs::function`"
        ));
        return;
    };
    if path.is_empty()
        || name.is_empty()
        || !name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        report.errors.push(format!(
            "entry {n}: `enforces` entry `{s}` must be `path/to/file.rs::function`"
        ));
        return;
    }
    let full = root.join(path);
    let text = match std::fs::read_to_string(&full) {
        Ok(t) => t,
        Err(_) => {
            report.errors.push(format!(
                "entry {n}: `enforces` file `{path}` does not exist in the tree"
            ));
            return;
        }
    };
    if !text.contains(&format!("fn {name}")) {
        report.errors.push(format!(
            "entry {n}: `enforces` `{s}` names no `fn {name}` in {path}"
        ));
    }
}

/// The base revision's `safety-argument.toml`, via `git show`. `Ok(None)`
/// when the base has no such file (e.g. a base predating the file).
fn base_document(root: &Path, base: &str) -> Result<Option<String>> {
    let out = Command::new("git")
        .args(["show", &format!("{base}:{SAFETY_ARGUMENT_REL}")])
        .current_dir(root)
        .output()
        .context("running `git show`")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("does not exist") || stderr.contains("exists on disk, but not in") {
            return Ok(None);
        }
        bail!(
            "`git show {base}:{SAFETY_ARGUMENT_REL}` failed: {}",
            stderr.trim()
        );
    }
    Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// Entries added or reworded since `base_doc` must carry all four linkage
/// fields. Pure: unit-tested without git.
///
/// Comparison is by (ref, argument) multiset, not by diff line: see the
/// module docs. An entry is new iff the base does not already contain that
/// exact claim; a reworded claim is therefore also new (it must carry
/// linkage, like any fresh claim), while a merely shifted or
/// metadata-annotated entry is not.
/// (ref, argument) claim identity, tolerant of the legacy pre-v2 shape
/// (`refs` array + `claim` instead of `ref` + `argument`): a normalized
/// entry is the same claim as its legacy form, so normalizing an entry's
/// keys must not make it look new.
fn claim_key(entry: &toml::Value) -> (String, String) {
    let Some(t) = entry.as_table() else {
        return (String::new(), String::new());
    };
    let r = t
        .get("ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            t.get("refs")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let a = t
        .get("argument")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| t.get("claim").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_default();
    (r, a)
}

fn enforce_new_entry_linkage(doc: &str, base_doc: &str, report: &mut CheckReport) {
    let value: toml::Value = match doc.parse() {
        Ok(v) => v,
        Err(_) => return, // already reported by check_document
    };
    let Some(entries) = value.get("invariants_preserved").and_then(|v| v.as_array()) else {
        return;
    };
    let base_value: toml::Value = match base_doc.parse() {
        Ok(v) => v,
        Err(_) => return, // base predates schema v2; cannot compare claims
    };
    let mut base_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    if let Some(base_entries) = base_value
        .get("invariants_preserved")
        .and_then(|v| v.as_array())
    {
        for e in base_entries {
            let key = claim_key(e);
            *base_counts.entry(key).or_insert(0) += 1;
        }
    }
    for (idx, entry) in entries.iter().enumerate() {
        let Some(t) = entry.as_table() else {
            continue;
        };
        let key = claim_key(entry);
        match base_counts.get_mut(&key) {
            Some(count) if *count > 0 => {
                *count -= 1; // pre-existing claim, not new
            }
            _ => {
                let n = idx + 1;
                for field in ["pr", "commit", "files", "enforces"] {
                    let present = match t.get(field) {
                        Some(toml::Value::Array(a)) => !a.is_empty(),
                        Some(_) => true,
                        None => false,
                    };
                    if !present {
                        report.errors.push(format!(
                            "entry {n} (new since base): missing required linkage field `{field}` — \
                             new safety-argument entries must carry `pr`, `commit`, `files`, and `enforces`"
                        ));
                    }
                }
            }
        }
    }
}

fn print_report(file: &Path, report: &CheckReport) {
    println!(
        "safety-argument: {} — {} entries",
        file.display(),
        report.total_entries
    );
    println!("  unique refs covered: {}", report.unique_refs);
    let mut top: Vec<(&String, &usize)> = report.ref_counts.iter().collect();
    top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (r, c) in top.iter().take(5) {
        println!("  {c:>4}  {r}");
    }
    println!(
        "  retired-ref entries (grandfathered L75): {}",
        report.retired_entries
    );
    println!(
        "  entries without linkage (legacy): {}",
        report.entries_without_linkage
    );
    for w in &report.warnings {
        eprintln!("warning: {w}");
    }
    if report.errors.is_empty() {
        println!(
            "safety-argument check passed ({} warning(s))",
            report.warnings.len()
        );
    } else {
        for e in &report.errors {
            eprintln!("error: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A scratch root with a fake spec (80 lines; L39/L42 live, L50 empty,
    /// L75 the retired filing rule) and a fake source file for `enforces`.
    fn fixture_root() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("narf-safety-arg-test-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("security-model/specification")).unwrap();
        fs::create_dir_all(root.join("memory/src")).unwrap();
        let mut spec = String::new();
        for i in 1..=80 {
            let line = match i {
                39 => "The TCB is strictly {frame/, memory/, capabilities/, scheduler/}.",
                42 => {
                    "Every kernel-side data access is covered by both a cap check and a domain tag."
                }
                75 => "Anything not listed above is a hole, and must be filed as a security bug.",
                50 => "",
                _ => "filler line of the security-model specification.",
            };
            spec.push_str(line);
            spec.push('\n');
        }
        fs::write(root.join(SPEC_REL), spec).unwrap();
        fs::write(
            root.join("memory/src/wx.rs"),
            "pub fn jit_cap_default_policy(task: u64) -> Option<JitCap> { None }\n\
             pub fn jit_mprotect() {}\n",
        )
        .unwrap();
        fs::write(root.join("memory/src/bpf_text.rs"), "pub fn alloc() {}\n").unwrap();
        root
    }

    fn spec_text(root: &Path) -> String {
        fs::read_to_string(root.join(SPEC_REL)).unwrap()
    }

    fn good_doc() -> String {
        r#"[safety_argument]
schema_version = 2

[[invariants_preserved]]
ref = "security-model/specification/spec.md#L42"
argument = "Change touches no cap check and no domain tag."
pr = 1284
commit = "66beee0a6b4f8f47f2168f015a39bd1d6ff9bceb"
files = ["memory/src/wx.rs"]
enforces = ["memory/src/wx.rs::jit_cap_default_policy"]
"#
        .to_string()
    }

    #[test]
    fn good_document_passes() {
        let root = fixture_root();
        let report = check_document(&good_doc(), &spec_text(&root), &root);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.total_entries, 1);
        assert_eq!(report.unique_refs, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_ref_line_beyond_spec_fails() {
        let root = fixture_root();
        let doc = good_doc().replace("#L42", "#L999");
        let report = check_document(&doc, &spec_text(&root), &root);
        assert_eq!(report.errors.len(), 1);
        assert!(
            report.errors[0].contains("beyond the end"),
            "{}",
            report.errors[0]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ref_to_empty_spec_line_fails() {
        let root = fixture_root();
        let doc = good_doc().replace("#L42", "#L50");
        let report = check_document(&doc, &spec_text(&root), &root);
        assert_eq!(report.errors.len(), 1);
        assert!(
            report.errors[0].contains("empty spec line"),
            "{}",
            report.errors[0]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn malformed_ref_fails() {
        let root = fixture_root();
        let doc = good_doc().replace(
            "security-model/specification/spec.md#L42",
            "somewhere-else.md#L42",
        );
        let report = check_document(&doc, &spec_text(&root), &root);
        assert_eq!(report.errors.len(), 1);
        assert!(
            report.errors[0].contains("malformed"),
            "{}",
            report.errors[0]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn retired_l75_without_flag_fails_and_with_flag_passes() {
        let root = fixture_root();
        let doc = good_doc().replace("#L42", "#L75");
        let report = check_document(&doc, &spec_text(&root), &root);
        assert_eq!(report.errors.len(), 1);
        assert!(
            report.errors[0].contains("retired line L75"),
            "{}",
            report.errors[0]
        );
        assert_eq!(report.retired_entries, 1);

        let doc2 = doc.replace(
            "ref = \"security-model/specification/spec.md#L75\"",
            "ref = \"security-model/specification/spec.md#L75\"\nretired_ref = true",
        );
        let report2 = check_document(&doc2, &spec_text(&root), &root);
        assert!(report2.errors.is_empty(), "{:?}", report2.errors);
        assert_eq!(report2.retired_entries, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn schema_version_1_fails() {
        let root = fixture_root();
        let doc = good_doc().replace("schema_version = 2", "schema_version = 1");
        let report = check_document(&doc, &spec_text(&root), &root);
        assert!(report
            .errors
            .iter()
            .any(|e| e.contains("schema_version is 1")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_argument_fails() {
        let root = fixture_root();
        let doc = good_doc().replace(
            "argument = \"Change touches no cap check and no domain tag.\"\n",
            "",
        );
        let report = check_document(&doc, &spec_text(&root), &root);
        assert!(report.errors.iter().any(|e| e.contains("argument")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn malformed_linkage_fields_fail() {
        let root = fixture_root();
        let cases = [
            (good_doc().replace("pr = 1284", "pr = 0"), "pr"),
            (good_doc().replace("pr = 1284", "pr = \"1284\""), "pr"),
            (
                good_doc().replace(
                    "commit = \"66beee0a6b4f8f47f2168f015a39bd1d6ff9bceb\"",
                    "commit = \"xyz\"",
                ),
                "commit",
            ),
            (
                good_doc().replace("files = [\"memory/src/wx.rs\"]", "files = []"),
                "files",
            ),
            (
                good_doc().replace(
                    "files = [\"memory/src/wx.rs\"]",
                    "files = [\"memory/src/nope.rs\"]",
                ),
                "does not exist",
            ),
            (
                good_doc().replace(
                    "enforces = [\"memory/src/wx.rs::jit_cap_default_policy\"]",
                    "enforces = [\"memory/src/wx.rs::no_such_fn\"]",
                ),
                "names no `fn no_such_fn`",
            ),
            (
                good_doc().replace(
                    "enforces = [\"memory/src/wx.rs::jit_cap_default_policy\"]",
                    "enforces = [\"memory/src/nope.rs::jit_cap_default_policy\"]",
                ),
                "does not exist",
            ),
            (
                good_doc().replace(
                    "enforces = [\"memory/src/wx.rs::jit_cap_default_policy\"]",
                    "enforces = [\"memory/src/wx.rs\"]",
                ),
                "must be `path/to/file.rs::function`",
            ),
        ];
        for (doc, needle) in cases {
            let report = check_document(&doc, &spec_text(&root), &root);
            assert_eq!(report.errors.len(), 1, "doc {doc:?} -> {:?}", report.errors);
            assert!(report.errors[0].contains(needle), "{}", report.errors[0]);
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn new_entry_detection_is_content_based_not_line_based() {
        // Regression test for the diff-alignment trap: inserting lines
        // above the entries shifts every header, and unified diffs align
        // the repeated `[[invariants_preserved]]` headers arbitrarily, so
        // a line-based "added entry" detector reports pre-existing entries
        // as new. Content comparison must not.
        let root = fixture_root();
        let base = good_doc();
        // Same claim, only a header comment inserted above it: not new.
        let shifted = base.replace(
            "[safety_argument]\nschema_version = 2\n",
            "[safety_argument]\nschema_version = 2\n# a long comment block\n# that shifts every line below it\n",
        );
        let mut report = CheckReport::default();
        enforce_new_entry_linkage(&shifted, &base, &mut report);
        assert!(report.errors.is_empty(), "{:?}", report.errors);

        // Same claim with only linkage metadata changed: not new either.
        let annotated = base.replace(
            "files = [\"memory/src/wx.rs\"]",
            "files = [\"memory/src/wx.rs\", \"memory/src/bpf_text.rs\"]",
        );
        let mut report = CheckReport::default();
        enforce_new_entry_linkage(&annotated, &base, &mut report);
        assert!(report.errors.is_empty(), "{:?}", report.errors);

        // A reworded claim with its linkage stripped IS new.
        let reworded = base
            .replace("no cap check", "no capability check")
            .replace("pr = 1284\n", "")
            .replace(
                "commit = \"66beee0a6b4f8f47f2168f015a39bd1d6ff9bceb\"\n",
                "",
            )
            .replace("files = [\"memory/src/wx.rs\"]\n", "")
            .replace(
                "enforces = [\"memory/src/wx.rs::jit_cap_default_policy\"]\n",
                "",
            );
        let mut report = CheckReport::default();
        enforce_new_entry_linkage(&reworded, &base, &mut report);
        assert_eq!(report.errors.len(), 4, "{:?}", report.errors);
        assert!(report.errors.iter().all(|e| e.contains("new since base")));

        // A legacy-shaped base entry (refs array + claim) normalized to
        // ref + argument is the same claim, not a new one.
        let legacy_base = "[safety_argument]\nschema_version = 1\n\n[[invariants_preserved]]\nrefs = [\"security-model/specification/spec.md#L42\"]\nclaim = \"Change touches no cap check and no domain tag.\"\n";
        let normalized = "[safety_argument]\nschema_version = 2\n\n[[invariants_preserved]]\nref = \"security-model/specification/spec.md#L42\"\nargument = \"Change touches no cap check and no domain tag.\"\npr = 1284\ncommit = \"66beee0a\"\nfiles = [\"memory/src/wx.rs\"]\nenforces = [\"memory/src/wx.rs::jit_mprotect\"]\n";
        let mut report = CheckReport::default();
        enforce_new_entry_linkage(normalized, legacy_base, &mut report);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn new_entry_linkage_required_in_diff_mode() {
        let root = fixture_root();
        let base = good_doc();
        let mut doc = base.clone();
        doc.push_str(
            "\n[[invariants_preserved]]\nref = \"security-model/specification/spec.md#L39\"\nargument = \"A new claim with no linkage.\"\n",
        );
        let mut report = check_document(&doc, &spec_text(&root), &root);
        // Full-file check passes (legacy warning only); diff mode must fail it.
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        enforce_new_entry_linkage(&doc, &base, &mut report);
        assert_eq!(report.errors.len(), 4, "{:?}", report.errors);
        assert!(report.errors.iter().all(|e| e.contains("new since base")));

        // Now give it full linkage: diff mode passes.
        let doc2 = doc.replace(
            "argument = \"A new claim with no linkage.\"",
            "argument = \"A new claim with no linkage.\"\npr = 1284\ncommit = \"66beee0a\"\nfiles = [\"memory/src/wx.rs\"]\nenforces = [\"memory/src/wx.rs::jit_mprotect\"]",
        );
        let mut report2 = check_document(&doc2, &spec_text(&root), &root);
        enforce_new_entry_linkage(&doc2, &base, &mut report2);
        assert!(report2.errors.is_empty(), "{:?}", report2.errors);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn real_repo_file_passes() {
        // Guard: the in-tree file must pass its own checker. Root is the
        // workspace root (build/xtask is two levels below it).
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
        let doc = fs::read_to_string(root.join(SAFETY_ARGUMENT_REL)).unwrap();
        let spec = fs::read_to_string(root.join(SPEC_REL)).unwrap();
        let report = check_document(&doc, &spec, &root);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.total_entries, 526);
        assert_eq!(report.retired_entries, 98);
    }
}
