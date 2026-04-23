# process — Research

## Primary sources

- **Linux kernel `Documentation/process/`** — submitting patches,
  maintainer PGP guide, security bugs.
  <https://docs.kernel.org/process/index.html>
- **OpenSSF "Secure Software Development Framework" (SSDF, NIST SP 800-218)**.
  <https://csrc.nist.gov/Projects/ssdf>
- **Rust Project Security Policy** — precedent for a Rust-ecosystem project.
  <https://www.rust-lang.org/policies/security>
- **FIRST CVSS 3.1 Specification**. <https://www.first.org/cvss/v3.1/specification-document>
- **SLSA (Supply-chain Levels for Software Artifacts)** — provenance
  framework relevant to AI-agent audit trails.
  <https://slsa.dev/>

## Secondary sources

- **Mozilla's Bug Bounty / Security Bug Process** — good reference for
  coordinated disclosure.
- **"Why Successful Software Has No Process Document" — Hillel Wayne**
  (counter-point; keeps us honest about process overhead).
  <https://www.hillelwayne.com/post/no-process/>
- **OpenSSF "AI-assisted security review" discussions** — emerging
  best-practice on AI agents in security workflows.
- **GitHub Copilot / AI-assisted coding policies** from major OSS
  projects (Kernel, Python, Rust) — precedent for AI contributor rules.

## Distilled summaries

- [`summaries/linux-kernel-process.md`](./summaries/linux-kernel-process.md)
  — Linux kernel development process, patch submission, maintainer protocols.
- [`summaries/openssf-ssdf.md`](./summaries/openssf-ssdf.md) — NIST SSDF secure development practices, maturity levels.
- [`summaries/rust-security-policy.md`](./summaries/rust-security-policy.md)
  — Rust Project security reporting, embargo protocol, advisory process.
- [`summaries/cvss-v31-specification.md`](./summaries/cvss-v31-specification.md)
  — CVSS v3.1 severity scoring for vulnerability classification.
- [`summaries/slsa-supply-chain.md`](./summaries/slsa-supply-chain.md)
  — SLSA levels, provenance attestations, build reproducibility.

## Fetched this round

### 2026-04-22
- linux-kernel-process.md (fallback)
- openssf-ssdf.md (fallback)
- rust-security-policy.md (fallback)
- cvss-v31-specification.md (fallback)
- slsa-supply-chain.md (fallback)

## Open research questions

- Concrete AI-agent attribution format (SLSA + in-toto attestations vs.
  simpler signed trailer).
- How to make the "security argument" AI agents must attach to TCB
  changes (§6.3) machine-checkable, not just human-readable prose.
- Do we adopt conventional-commits or a custom commit-message format?
- Release cadence — time-based (every N weeks) or train-based (when
  the next stage's exit criterion passes)?
