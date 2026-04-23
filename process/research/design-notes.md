# process — Design Notes

## Iteration 2026-04-22

---

## Load-bearing decisions

**AI agents are first-class contributors, not guests.** The spec encodes this by assigning a full "Proposing" tier with defined obligations (originating prompt, model+version, Co-Authored-By trailer). The implication is that the audit trail infrastructure — which doesn't exist yet — is load-bearing from day one, not a Stage 4 afterthought. If that trail can't be queried by a maintainer, the entire AI-agent tier collapses into unverified trust.

**TCB classification is binary and early-gated.** There is no "probably TCB" grey zone. The spec draws the line at five named folders and makes "TCB" a hard change class with two maintainers + security-review mandatory. This is load-bearing: a design that allowed "TCB-lite" changes to slip through Standard review would erode the entire trust model. The current boundary is defensible but depends heavily on `capabilities/` staying cleanly separate from `scheduler/` internals — which the framekernel design strains (the executor core is TCB, but task management lives right next to it).

**Coordinated disclosure with fixed embargo windows.** The 14/30/60/∞ day ladder is borrowed from the Rust Project security policy. The load-bearing assumption is that the security team is reachable within 2 business days — fine for a project with a maintainer, dangerous if maintainers become unavailable simultaneously. No deputy / rotation policy exists.

**No concrete issue tracker or review platform specified.** This is intentionally deferred but creates a gap: process/§9 merge gate #7 (perf gate) requires a CI runner with specific hardware properties, but the spec never names a CI system. All "CI green" language is aspirational.

---

## Divergences from precedent

**Linux kernel process:** Linux has no formal AI-agent tier — an equivalent change would be submitted as a human contribution or not at all. NARF's explicit AI-agent rules (§6) are genuinely novel and represent a stronger stance than any mainstream OSS project. The Linux process also has no per-change "safety argument" requirement for TCB changes; NARF's §6.3 mandatory safety argument prose is borrowed from seL4's review culture, not Linux's. The SLSA provenance research suggests this is the right direction (SLSA Level 3 requires traceable build provenance; NARF adds traceable *authorship* provenance), but the machine-checkability open question is real.

**Rust Project security policy:** NARF follows the embargo-period ladder closely but diverges in one important way — the Rust Project has a single security team with rotation and succession planning, while NARF's §8 silently assumes one or two maintainers hold the private channel. For an OS project that will be deployed, the single-team assumption is fragile.

**Fuchsia (Google-backed):** Fuchsia has entire infrastructure teams — separate from engineers — who own release infrastructure, signing keys, and SLSA attestations. NARF has none of that yet. The spec's release-signing rule (§11, maintainer signs, AI may not) is correct but relies on exactly one human with a signing key at any time.

**OpenSSF SSDF maturity model:** The SSDF suggests defining what qualifies as a security bug before accepting code, which maps to NARF's §7.3 triage. But SSDF PO.3 (security training) is entirely absent from NARF's process. The spec assumes contributors understand the threat model; nowhere does it mandate that understanding be demonstrated. For AI agents this is especially relevant: an agent can generate a safety argument that looks correct but rests on a misunderstood invariant.

---

## Proposed spec changes

- §6.3 TCB changes by AI agents: **Add a machine-checkable safety-argument schema** — require the agent to enumerate which invariants from `security-model/§4` are claimed preserved and cross-reference them by section+line. Prose safety arguments are too easy to pass review without actual coverage. Why: an LLM can produce convincing but vacuous prose; a structured schema forces precision and enables automated consistency checking.

- §6.5 Audit trail: **Specify a concrete format (SLSA in-toto + custom `narf-agent` attestation layer) before Stage 2.** The current "retained for at least one release cycle" is unactionable without a format and storage location. Why: the SLSA research shows Level 1 provenance is cheap to achieve early; deferring costs a lot to retrofit.

- §8.1 Reporting: **Name a deputy and rotation cadence for the private security channel.** Currently implies a single contact. Why: single points of failure in disclosure are a known failure mode (see Heartbleed initial patch delay); NARF's small team makes this worse, not better.

- §9 Merge gates: **Gate #1 (build) must explicitly list minimum Rust toolchain channel (stable/nightly) and minimum LLVM version.** "Build green" is meaningless without a pinned toolchain. Why: LTO + `build-std` are nightly features in practice; if CI silently uses nightly and a human uses stable, the gates diverge.

- §4 Change classification: **Add a "Performance-sensitive" marker as a formal modifier** (not a class) that any Standard or Interface change can carry. Currently §9 gate #7 refers to a `perf-sensitive` tag that has no definition in §4. Why: the verification spec §8 statistical protocol is only triggered by this tag, but the tag is never defined or assigned by any process step.

- §6.4 Forbidden agent actions: **Explicitly prohibit agents from approving other agents' PRs.** The current text says AI reviews are "advisory," but never states they cannot approve. A CI bot approving an agent PR would technically satisfy the letter of the review bar if the bot has maintainer rights. Why: this is an obvious loophole once project automation grows.

- §11 Releases: **Adopt a pre-1.0 version scheme aligned with roadmap stages** (e.g. `0.1.x` = Stage 1, `0.2.x` = Stage 2). The current "pre-1.0 sequence" is unspecified, which makes "affected versions" in NSAs (§8.4) ambiguous. Why: every security advisory requires a version range; without it, disclosure cannot be acted on.

---

## Open invariants / cross-subsystem hazards

**process §6.3 ↔ security-model §4 (TCB boundary):** The TCB definition in `process/` names five folders. But `security-model/` §4 says "anything outside this set is untrusted relative to the framekernel guarantees." If a subsystem (say, `interrupts/` or `rcu/`) has a safety property that, when violated, compromises the executor core (which is TCB), the TCB boundary in `process/` needs to expand — or the architectural claim that they are isolated is overstated. This is not currently tracked anywhere.

**process §9 (merge gates) ↔ verification §8 (statistical protocol):** Gate #7 references the statistical protocol but `process/` §9 doesn't specify *who* runs the perf CI or on what hardware class. The `verification/` spec §8.2 requires dedicated cores with fixed frequency — but process has no enforcement path if the CI runner doesn't meet those requirements. A regression on a noisy shared runner still passes gate #7 if nothing catches the runner condition.

**process §6.5 (audit trail) ↔ tracing §3.4 (tracer task):** The spec mandates an audit trail for AI-agent actions. The `tracing/` subsystem has a tracer task and cap-gated event streams. There is no specification of whether the AI-agent audit trail uses the tracing infrastructure or is independent. If it uses `tracing/`, then tracing becomes TCB for audit purposes — which the tracing spec does not claim. If it's independent, we duplicate infrastructure. Needs explicit decision before Stage 2.

**process §8.3 (security fix) ↔ verification §5 (property tests):** The spec allows a "sanitised marker test" when the exploit test demonstrates exploitation. But property tests (proptest/arbtest) that exercise the boundary may accidentally trigger the exploit. The interaction between property-test corpus and embargoed vulns is not addressed.

---

## Additional opinionated commentary

The spec's most dangerous omission is the absence of a **principal hierarchy for capability escalation within the process itself**. Who can override a rejected security argument? Who resolves a dispute between two maintainers where one believes a change is TCB and the other doesn't? Linux has BDFL-fallback via Linus; seL4 has the UNSW trustworthy systems group. NARF names no tie-breaker.

The "fresh PR from a fresh prompt" rule in §6.3 — required when a reviewer believes an AI agent's safety argument is wrong — is the right instinct but creates a subtle perverse incentive: an agent that learns it will be rejected may start generating more elaborate but still incorrect arguments to pass review. Machine-checkable invariant enumeration (see proposal above) is the only structural remedy.

The SSDF research documents a common failure: "checklist theater" where security practices are adopted for compliance, not effect. NARF's §6.3 TCB safety-argument requirement risks exactly this if it becomes a pro-forma paragraph every agent includes. The spec needs a test for argument quality, not just argument presence.
