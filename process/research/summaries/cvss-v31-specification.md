# FIRST CVSS 3.1 Specification

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## CVSS as a Vulnerability Severity Language for NARF

The Common Vulnerability Scoring System (CVSS) v3.1 provides a standardized vocabulary for describing software vulnerabilities. NARF should use CVSS scores in security advisories to communicate severity to users and integrators in a comparable, reproducible format.

## Scoring Vector and NARF's Application

CVSS v3.1 breaks vulnerabilities into base, temporal, and environmental metrics:

**Base Metrics** (immutable; characterize the flaw itself):
- **Attack Vector (AV)**: Network (N), Adjacent (A), Local (L), Physical (P). A capability bypass exploitable via IPC is AV:N; one requiring kernel-level privileges is AV:L.
- **Attack Complexity (AC)**: Low (L) or High (H). A capability check that always fails is AC:L; one exploitable only under race conditions is AC:H.
- **Privileges Required (PR)**: None (N), Low (L), High (H). A flaw in the base kernel requires PR:N; a flaw in admin-only subsystem requires PR:H.
- **User Interaction (UI)**: None (N) or Required (R). Most kernel bugs are UI:N; a flaw triggered only by malformed user input might be UI:R.
- **Scope (S)**: Unchanged (U) or Changed (C). Domain isolation bypass affecting other domains is S:C; a single-domain capability leak is S:U.
- **Confidentiality/Integrity/Availability (C/I/A)**: None (N), Low (L), High (H). IPC eavesdropping is C:H; capability forge is I:H; denial-of-service is A:H.

**Example**: A capability-table corruption bug exploitable via a malformed IPC message, requiring no privileges, under normal operation, affecting other domains' integrity scores: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H = CVSS 9.1 (Critical).

**Temporal Metrics**: Account for exploit availability (E), patch availability (RL), and verified exploitability (EX). Initially, E:U (unproven); after PoC release, E:P; after patch merge, RL:O (official fix).

**Environmental Metrics**: Allow consumers to adjust scores based on deployment context. A capability bypass in a userspace driver is C:H but might be Environmental:L if the driver runs in a sandboxed domain.

## Invariants to Maintain

- **Consistency**: Use the same scoring methodology for all NARF vulnerabilities; document scoring rationale in advisories
- **Transparency**: Publish the CVSS vector string, not just the numeric score (e.g., 7.5 is meaningless without the vector)
- **No Score Gaming**: Resist pressure to under-score "important-but-not-critical" issues; CVSS scores drive patching prioritization

## Performance Trade-offs

CVSS scoring adds ~1 hour of work per advisory (researching exploitability, scope impact, privileges required) but standardizes risk communication. Users trust CVSS more than ad-hoc severity labels ("critical", "high").

## Pitfalls to Avoid

- **Vector Inflation**: If "potential for privilege escalation" inflates all capability bugs to Critical, the scoring system loses discriminative power
- **Retroactive Rescoring**: Avoid changing historical scores; instead, issue clarifications with context
- **Scope Ambiguity**: If NARF's domains/capabilities architecture is poorly documented, estimating "Scope Changed" becomes guesswork

## Recommendation

For each security advisory, include a CVSS v3.1 vector string and brief scoring justification (2-3 sentences). Link to the CVSS calculator (https://www.first.org/cvss/calculator/3.1) to allow consumers to adjust environmental metrics for their deployments. Maintain an advisories/cvss-template.md documenting your scoring conventions.

https://www.first.org/cvss/v3.1/specification-document
