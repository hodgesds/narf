# process — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> review process, change classification, and AI-agent
> protocol; v1.0 locks the issue-tracker conventions, the
> CODEOWNERS layout, the conflict-of-interest rules, the CVSS
> profile, the LTS window policy, and the agent-provenance
> format.
> Treat this spec as *binding on both humans and AI agents*.

## 1. Purpose & scope

**Owns:** The rules humans and AI agents follow when contributing to,
reviewing, or releasing NARF. Change classification, review bars,
bug-intake flow, security disclosure, merge gates, AI-agent rules of
engagement, audit-trail requirements.

**Does NOT own:** Technical specifications of code (those live in each
subsystem's spec). What to test (that's `verification/`). How tools
work (that's `build/`).

## 2. Assumptions

- Version control: git. Mainline branch name: `main`.
- Issue tracker and review platform exist (concrete tool is
  deployment-specific and out of scope).
- At least one human maintainer with merge rights exists at all times.
- AI agents have identifiable, auditable accounts distinct from human
  contributors.

## 3. Actors

Three actor classes, with explicit authority boundaries:

| Actor               | May propose | May review | May merge | May sign releases | May touch TCB |
| ------------------- |:-----------:|:----------:|:---------:|:-----------------:|:-------------:|
| Maintainer (human)  | ●           | ●          | ● (gated) | ●                 | ●             |
| Contributor (human) | ●           | ● (advisory) | ✗       | ✗                 | ● (via PR)    |
| AI agent            | ●           | ● (advisory) | ✗       | ✗                 | ◐ (see §6.3)  |

Legend: ● allowed, ◐ conditionally, ✗ forbidden.

"TCB" means code in `frame/`, `memory/` domain manager,
`capabilities/`, executor core in `scheduler/`, `security-model/`
content, or anything the security model names as trusted.

## 4. Change classification

Every change is classified at proposal time; classification drives the
review bar:

- **Trivial** — documentation typos, comment cleanup, formatting-only
  diffs. One reviewer, CI green, merge.
- **Standard** — a bug fix or feature that does not touch the TCB and
  does not change a public subsystem interface. Two reviewers (one
  subsystem owner), CI green.
- **Interface** — modifies a `specification/spec.md` public-interface
  section, ABI, or cross-subsystem contract. Subsystem owner + one
  additional maintainer. Spec change must be part of the same PR.
- **TCB** — touches TCB code as defined above. Two maintainers, one
  must be a security reviewer. Mandatory `security-review` skill pass.
  Commit must be signed.
- **Security-critical** — fixes a CVE or modifies the threat boundary.
  §7 flow applies. Not a normal PR.

Misclassification is a review finding, not a cause for merge.

## 5. Contribution flow (normal path)

1. **Intent** — an issue is opened describing the problem or feature,
   classified per §4. For AI agents, the agent's originating task
   prompt is attached to the issue.
2. **Branch** — short-lived topic branch off `main`. Naming convention:
   `<actor-id>/<short-slug>`.
3. **Implementation** — code changes, spec updates when applicable,
   tests per `verification/`.
4. **Self-check** — actor runs the local gate: build, unit tests,
   functional tests relevant to changed subsystems, clippy + fmt.
5. **PR opened** — PR description includes: change class (§4),
   subsystems touched, spec sections touched, security impact, test
   plan, statistical evidence for any perf claims (§ `verification/`).
   For AI-originated PRs, the originating prompt is part of the
   description.
6. **CI** — required checks per §9.
7. **Review** — per §4 bar. Review comments from AI review agents are
   *advisory* — a human must explicitly accept or override them.
8. **Merge** — maintainer merges. Squash-merges preferred; merge commit
   message cites the PR and classifies the change.
9. **Post-merge** — if a change affected a spec, the glossary or
   `ROADMAP.md` mentions update in the same PR.

## 6. AI agent rules of engagement

### 6.1 Identity and attribution

- Every AI agent has a distinct account.
- Every commit proposed by an AI agent is signed by that agent's
  account or co-authored trailer (`Co-Authored-By: <agent> <noreply@…>`).
- The agent's model, version, and the originating prompt are recorded
  in the PR description. This is non-negotiable: a reviewer must be
  able to see exactly which prompt produced the diff.

### 6.2 Autonomy tiers

Three tiers of agent action, from least to most supervised:

1. **Advisory** — the agent comments on PRs, suggests changes, runs
   analyses. No write access to the repository.
2. **Proposing** — the agent opens PRs. All PRs go through the normal
   review flow per §4. Default for coding agents.
3. **Merge-gated** — an agent may *never* merge to `main`, regardless
   of CI status. Merges require a human maintainer action.

### 6.3 TCB changes by AI agents

AI agents may propose TCB changes (Trivial or Standard classification
never applies; default to TCB), but the review bar of §4 applies:

- Two maintainers review, one must be a security reviewer.
- A `security-review` pass is mandatory.
- The agent must include, in the PR description, an explicit safety
  argument **in the schema below** — prose alone is not accepted.
- If any reviewer believes the agent's safety argument is wrong, the
  PR is closed, not iterated. A new PR must start from a fresh prompt.

**Machine-checkable safety-argument schema (binding from Stage 2).**
Every AI-originated TCB PR includes a `safety-argument.toml` block
with:

```toml
[safety_argument]
schema_version = 1
agent          = "<agent-name@version>"
prompt_hash    = "<sha256 of the originating prompt>"

# One entry per security-model invariant claimed preserved.
# Each entry references the section.line in security-model/specification/spec.md
# at the commit being reviewed. CI verifies the references exist.
[[invariants_preserved]]
ref       = "security-model/specification/spec.md#L34"  # TCB-set definition
argument  = "Change is in capabilities/ which is already in the TCB set; no boundary moved."

[[invariants_preserved]]
ref       = "security-model/specification/spec.md#L37"  # cap-AND-domain rule
argument  = "Edit only adds a new cap operation; both checks remain in place."
```

A linter run by CI parses the file, verifies each `ref` resolves to
a present line, and counts unique invariants covered. The schema is
not the safety argument — it is its skeleton; reviewers still read
the prose. But missing or unresolvable refs are a hard merge-block.

### 6.5 Audit trail (concrete format from Stage 2)

The pre-Stage-2 wording ("retained for at least one release cycle")
is unactionable without a format. Adopting:

- **Wrapper:** SLSA in-toto attestation envelope (`statement_type:
  https://in-toto.io/Statement/v1`).
- **Predicate:** custom `narf-agent` predicate with shape:

  ```json
  {
    "predicateType": "https://narf.os/agent/v1",
    "predicate": {
      "agent":         { "name": "...", "model": "...", "version": "..." },
      "prompt":        { "sha256": "...", "redacted_excerpt": "first 200 chars" },
      "tool_calls":    [ /* sequence of {tool, args_hash, result_hash} */ ],
      "files_changed": [ /* paths + before/after sha256 */ ],
      "review":        { "reviewers": [...], "approved_at": "..." }
    }
  }
  ```

- **Storage:** signed by the agent's per-account key (rotated per
  `crypto/` §4) and stored under `.narf/attestations/` in the repo.
  One attestation per merged PR.

This achieves SLSA Level 1 provenance from day one of Stage 2 and
positions us for Level 2/3 (signed builds, hosted build platforms)
as those mature.

### 6.4 Forbidden agent actions

AI agents may not:

- Modify `process/specification/spec.md` without an explicit human
  prompt saying so.
- Modify `security-model/specification/spec.md` without an explicit
  human prompt and Security-critical classification.
- Push directly to `main`, sign releases, or mint capabilities that
  would grant ambient authority in the running system.
- Use secrets (API keys, signing keys) that are not scoped to a single
  automated task.

### 6.5 Audit trail

All agent actions produce an audit record: prompt → tool calls → file
diffs → PR → review outcomes. The record is retained for at least one
release cycle and is available to any maintainer on request.

## 7. Bug handling

### 7.1 Intake

Any actor may file a bug. Bug reports include:

- **Summary.** One sentence.
- **Environment.** NARF revision, target arch, bootloader, QEMU /
  hardware.
- **Reproduction.** Minimal steps, ideally a `cargo xtask test` command.
- **Expected vs. actual.** Precisely.
- **Severity guess.** Info / minor / major / critical. Triage may reclassify.

### 7.2 Triage

A maintainer (or designated triager) assigns:

- Severity (final).
- Subsystem owner.
- Class: bug, regression, performance regression, security (→ §7.3
  immediately), flake.

Performance regressions are handled per `verification/` statistical
protocol — a single-run slowdown is a flake until the statistical test
says otherwise.

### 7.3 Security bugs

A report that might be a security bug is triaged privately. See §8.

### 7.4 Fix flow

- Author opens a PR with the fix and a **regression test** under
  `verification/`. No regression test means no merge, except for
  build-breaks and trivial class.
- Reviewers confirm the test fails without the fix and passes with it.
- On merge, the issue is closed with the merge commit hash.

## 8. Security handling

NARF uses **coordinated disclosure**.

### 8.1 Reporting

- A dedicated private channel (encrypted email address plus backup)
  receives security reports.
- Reports are acknowledged within two business days.

### 8.2 Embargo

- The security team and the affected subsystem owner(s) analyse the
  report in a private branch/fork.
- An embargo date is set based on severity:
  - Critical: 14 days.
  - High: 30 days.
  - Medium: 60 days.
  - Low: handled in the next normal release, no embargo.
- The embargo window exists to ship a fix, not to delay one.

### 8.3 Fix

- Fix developed privately. Same review bar as a TCB change (§4).
- A regression test lands with the fix, *unless* the test itself would
  demonstrate exploitation — in which case a sanitised marker test
  lands instead and the exploit test is kept in a private security
  repository.

### 8.4 Disclosure

- On embargo expiry or fix release, a NARF Security Advisory (NSA) is
  published containing:
  - CVE number (if assigned).
  - Affected versions.
  - Severity per CVSS 3.1.
  - Technical description.
  - Credit to the reporter.
- `security-model/` is updated if the event changed the threat boundary
  or added a new mitigation.

### 8.5 AI-agent involvement in security work

- AI agents may be involved in vulnerability research and patch review.
- AI agents **may not** be the sole reviewer of a security fix.
- The same audit-trail rule (§6.5) applies with the additional
  restriction that prompts touching embargoed code must be logged in
  the private security repository, not the public one.

## 9. Merge gates

A PR may not merge unless every item below is green:

1. **Build** — both x86_64 and aarch64 kernels compile (release + debug).
2. **Lint** — `cargo clippy --all-targets -- -D warnings` passes.
3. **Format** — `cargo fmt --check` passes.
4. **Unit tests** — all unit tests green.
5. **Functional tests** — QEMU boot-and-probe suite green on both arches.
6. **Spec consistency** — if code in subsystem X changed its public
   interface, `X/specification/spec.md` §3 was updated in the same PR.
7. **Perf gate** — if the change is tagged `perf-sensitive`, the
   perf-regression CI (`verification/`) is green per the statistical
   protocol.
8. **Review bar** — per §4.

Maintainers may override any gate *except* #7 and #8 in documented
emergencies (e.g. unblocking a broken CI itself). Every override is
logged and reviewed retrospectively.

## 10. Commits

- Present-tense imperative subject line, ≤ 72 chars.
- Body explains *why*. What is visible in the diff.
- Trailers: `Fixes:` / `Refs:` linking issues; `Co-Authored-By:` for
  AI-assisted commits; `Reviewed-by:` after merge.
- Signed commits required for TCB and Security-critical changes.

## 11. Releases

- Semantic versioning: `MAJOR.MINOR.PATCH` on a stable ABI, plus a
  pre-1.0 sequence for the Stage-1..4 roadmap.
- Each release tag is signed by a maintainer. AI agents may not sign.
- Release notes call out: behaviour changes, ABI changes, security
  advisories resolved, perf movements (with confidence intervals).

## 12. Dependencies

- **Consumes:** `verification/` (gate definitions, stat methodology),
  `security-model/` (threat model, trust boundaries), `build/`
  (what "build green" means), `crypto/` (commit / release / AI-agent
  signing keys and rotation).
- **Provides to:** every other subsystem. This spec binds every
  contributor.

## 13. Stage assignment

Stage 1 (v0.1 adopted before first external PR).
Revised at the start of each stage with at minimum a short review.

## 14. Resolved decisions

### 14.1 Issue tracker / review platform (resolved)

**Decision:** **GitHub issues + PRs as the canonical
platform**. All spec wording assuming "PRs" / "review board"
maps to GitHub workflows.

Mirror to a self-hosted forge (Forgejo / Gitea) is permitted
for vendors who require offline development; the canonical
state is GitHub. PRs to the canonical repo are the official
record.

CI gates run via GitHub Actions; release tags are created in
GitHub.

### 14.2 CODEOWNERS (resolved)

**Decision:** **`CODEOWNERS` files added per top-level
subsystem** once that subsystem's spec is at v1.0. Each
subsystem maintains a `CODEOWNERS` listing 1-3 reviewers
required for any PR touching its files.

Cross-subsystem PRs (the common case for ABI changes) require
review from each affected `CODEOWNERS` set. Interface-class
changes (per §4) require additional review from a separate
"ABI-stewards" group.

### 14.3 Conflict-of-interest rules (resolved)

**Decision:** **author may not single-sign-off their own
work**. If a PR's only qualified reviewer is the author:

1. The PR is held until a second reviewer is found, OR
2. An ABI-steward (separate person from the author) reviews
   for soundness even if not subsystem-expert.

This bounds risk on small subsystem teams — the cost is some
PRs blocking on additional review. In practice this surfaces
the need to grow review depth; the steward's "I checked
soundness even though I'm not the expert" review is
explicitly logged.

### 14.4 CVSS profile (resolved)

**Decision:** **CVSS 4.0 from v1.0**. CVSS 3.1 is grandfathered
for historical CVEs only. New advisories use 4.0.

### 14.5 LTS windows (resolved)

**Decision:** **two LTS streams: 2-year and 5-year**.

- 2-year LTS: even-numbered minor releases (v1.0, v1.2, …).
  Receive bug fixes for 2 years, no new features.
- 5-year LTS: every fifth minor release (v1.0, v1.5, …).
  Receive critical bug fixes + security patches for 5 years.

A given release can be both (v1.0 is both 2-year and 5-year).
Vendors / system integrators pick which stream they track.
Out-of-tree drivers SHOULD specify which LTS stream(s) they
support in their `driver.toml`.

### 14.6 AI-agent provenance format (resolved)

**Decision:** **SLSA Provenance v1.0 + in-repo attestation
files**. Each AI-agent commit is accompanied by a signed
attestation in `attestations/<commit-sha>.intoto.jsonl`:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [{"name": "...", "digest": {"sha256": "..."}}],
  "predicate": {
    "buildDefinition": {"buildType": "narf-ai-agent/v1", ...},
    "runDetails": {"builder": {"id": "claude-opus-4-7"}, ...}
  }
}
```

This is human-readable, tooling-friendly, and standard. Tools
can verify the chain "code → AI agent → reviewing human → CI
build → release artefact" using existing SLSA infrastructure.

Agent signing keys per `crypto/spec` §9.7.

## 15. Open questions

(none — all v0.1 questions resolved in §14)
