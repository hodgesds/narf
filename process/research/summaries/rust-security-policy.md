# Rust Project Security Policy

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Policy Structure for NARF

The Rust Project's security policy provides a mature template for a language/ecosystem-scale project. NARF, as a systems library designed for integration into other projects, should adopt analogous structures at a smaller scale.

## Key Mechanisms

**Security Contact and Reporting**: The Rust Project maintains security@rust-lang.org with published response SLAs. NARF should establish security@narf-project.org (or equivalent) as the single point of entry for vulnerability reports. Publish the contact in README, SECURITY.md, and package metadata.

**Embargo Protocol**: Rust coordinates disclosure with major downstream consumers (distributions, high-profile projects) before public announcement. For NARF, identify critical consumers (e.g., projects integrating the kernel into products) and notify them ~1 week before CVE public release.

**Scope Definition**: Rust explicitly delineates what constitutes a reportable security issue (e.g., soundness bugs in std, not ergonomic API choices). NARF should define:
- In Scope: Capability bypass, domain isolation violation, IPC eavesdropping, covert channels
- Out of Scope: Performance regression, missing feature, documentation typo

**Transparency and Advisories**: After embargo expires, Rust publishes a detailed advisory explaining the vulnerability, impact, patches, and workarounds. NARF must do likewise: every security fix should have a corresponding advisory entry, even for pre-1.0 releases.

**Patch Release Schedule**: Rust releases security patches on a cadence aligned with its regular release train. NARF could adopt an ad-hoc model pre-1.0 (immediate release), then move to synchronized releases post-1.0.

## Invariants to Maintain

- **No Surprise CVEs**: Every major security issue (capability bypass, IPC breach) receives CVE assignment before public disclosure
- **Patch Availability**: Users have ≥2 weeks to update after fix release before exploit details become public (implicit embargo)
- **Historical Record**: An archive (docs/advisories/) lists all prior security incidents, fixes, and lessons learned

## Performance Trade-offs

Formal security advisory process adds 2-3 weeks of coordination overhead per incident but builds trust. Projects that silently merge security fixes without formal disclosure later suffer reputational damage when issues are retroactively discovered.

## Pitfalls to Avoid

- **Scope Creep**: If "security" expands to include "any change that might affect reliability," every bug becomes security-critical and advisory fatigue sets in
- **Embargo Leakage**: If embargoed patch details are visible in version control before the embargo window ends, adversaries exploit the gap
- **Unclear Fix Semantics**: If an advisory says "update to version X" but version X doesn't include the fix, users blame the project

## Recommendation

Publish NARF's Security Policy as SECURITY.md in the repo root; link from README. Establish security@narf contact immediately (even if it's a single person initially). Pre-commit a security/advisories/ folder with a template for future incidents. Review and update the policy annually or after each security incident.

https://www.rust-lang.org/policies/security
