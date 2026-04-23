# Linux Kernel Documentation/Process/

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Process Infrastructure for NARF Development

The Linux kernel's formal development process provides critical precedents for managing a complex, collaborative microkernel project like NARF. The kernel's subsystem-based organization, peer review discipline, and security incident handling offer proven patterns applicable to Rust framekernel development.

## Key Mechanisms

**Patch Submission and Review**: The kernel enforces a hierarchical review model—patches flow through subsystem maintainers, then to Linus via release managers. NARF should adopt equivalent gatekeeping: a designated process/ subsystem owner performs initial triage on all changes touching process/protocol, with escalation paths for security implications.

**Stable Maintainer Consensus**: The kernel identifies "stable" patches worthy of backporting through explicit tagging. For NARF, define which commits (capability system fixes, security patches) are backport candidates; maintain release branches with explicit cherry-pick records.

**Security Embargo Period**: The kernel coordinates CVE disclosure for timing 10-14 days ahead of public patch release. NARF must establish equivalent security@narf contact, reporter triage SLA, and patch preparation workflows before announcing vulnerabilities.

**Commit Message Discipline**: Kernel conventions require "Fixes: <commit-hash>" trailers linking bugfixes to the commits they repair. For NARF, adopt conventional-commits format with security implications flagged (e.g., "Fixes: caps/xxx Security: <brief>").

## Invariants to Maintain

- **Audit Trail**: Every change that touches TCB (kernel code handling capabilities, domain transitions, IPC) requires human sign-off; no automated squashing of reviewed commits
- **Release Readiness**: Before tagging a release, verify no pending security advisories; publish security policy contemporaneously
- **Contributor Attribution**: Commits preserve all Co-Authored-By and Reviewed-By trailers; SLSA provenance attaches to tagged releases

## Performance Trade-offs

Formal process adds latency to hotfixes (review cycles, embargo coordination) but prevents cascading incidents from undisclosed vulnerabilities. The kernel's decade of experience shows that 1-2 week review overhead saves months of incident response when flaws escape.

## Pitfalls to Avoid

- **Process Drift**: If subsystem maintainers bypass review for "urgent" changes, enforcement erodes—establish nonwaivable rules for TCB changes
- **Reviewer Overload**: Without clear scope boundaries (e.g., only capability system changes require security review, not driver changes), review queues accumulate
- **Disclosure Miscoordination**: If patch-release timing and embargo expiration desynchronize, attackers exploit the gap

## Recommendation

Establish a NARF Security Policy document (public) and internal Process Handbook (private security contacts, embargo timelines). Model both on the Linux kernel and Rust Project security policies. Require process/ subsystem review for all security-adjacent changes; delegate style/whitespace review to CI.

https://docs.kernel.org/process/index.html
