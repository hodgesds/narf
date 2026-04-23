# OpenSSF Secure Software Development Framework (SSDF, NIST SP 800-218)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Framework Structure and NARF Applicability

The NIST SSDF defines four core practices (PO, PI, PS, PV) organized hierarchically into maturity levels 1-4. NARF's stage-based development aligns naturally with this framework: Stage 1 (early kernel) likely targets SSDF Level 2 (reproducible security practices), while Stages 3-4 (hardened kernel + userspace) should achieve Level 3 (managed security controls).

## Key Mechanisms

**Practice PO: Preparation Organization** — Establish roles, security policies, and incident procedures before accepting code. For NARF: define security@narf contact, publish a vulnerability disclosure policy, document what qualifies as a security bug (capability bypass, IPC eavesdropping, timing covert channel).

**Practice PO.3: Security Training** — Contributors must understand threat models before modifying TCB code. Require all persons touching capabilities/ or scheduler/ subsystems to complete a NARF Security Essentials checklist (capability model, domain isolation, async safety).

**Practice PI: Protection Implementation** — Integrate security checks into development workflow. For NARF: merge-blocking checks for capability soundness (static analysis via Kani), domain-crossing safety assertions, IPC serialization correctness.

**Practice PI.1: Source Control** — Enforce branch protection, require peer review before merge, maintain audit log of all changes. NARF's GitHub Actions CI should reject unsigned commits and enforce merge-request review from qualified subsystem maintainers.

**Practice PS: Production and Supply Chain** — Ensure binaries are reproducible and provenance is trackable. NARF should publish build scripts, document compiler versions, use in-toto attestations to link commits to releases.

**Practice PV: Vulnerability Verification** — Establish fuzzing campaigns and regression test suites. For NARF: schedule weekly fuzzing runs on capability table corruption, IPC buffer boundary conditions, and async executor fairness.

## Invariants to Maintain

- **TCB Clarity**: Every file explicitly tagged (TCB=yes/no) based on whether malfunction breaks security properties; unmarked files default to no
- **Security Review SLA**: All TCB changes reviewed within 2 weeks; security-critical changes within 3 business days
- **Incident Tracking**: All security reports tracked in private issue queue with SLA-enforced responses

## Performance Trade-offs

Implementing SSDF Level 3 requires sustained engineering investment (security training, build infrastructure, fuzzing harnesses) but yields auditable evidence of due diligence. The cost scales with team size; a 5-person team can credibly achieve Level 3 with ~15% process overhead.

## Pitfalls to Avoid

- **Checklist Theater**: PO.3 training becomes rote if not paired with real threat scenarios (e.g., "could this change allow a compromised device driver to forge a capability?")
- **Review Asymmetry**: If some subsystems bypass PV testing because they're "obviously safe," regressions hide in assumptions rather than tests
- **Supply Chain Fragility**: If NARF depends on unvetted crates, SSDF proves only NARF's code, not its dependencies—explicitly scope SSDF claims

## Recommendation

Track SSDF maturity per subsystem. Stage 1 development should hit Level 2 on all subsystems. Before Stage 3 userspace enablement, achieve Level 3 on capabilities/, security-model/, and scheduler/ subsystems. Document the mapping in security-policy.md; update it annually.

https://csrc.nist.gov/Projects/ssdf
