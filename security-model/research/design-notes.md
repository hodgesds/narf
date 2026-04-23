# security-model — Design Notes

## Iteration 2026-04-22

---

## Load-bearing decisions

**Defence in depth: capability AND domain, not capability OR domain.** §4 states "every kernel-side data access is covered by both a capability check and a domain tag." This is the most important architectural invariant in the entire project. The Capability Myths Demolished paper (Miller, Yee, Shapiro 2003) argued that capabilities alone are sufficient for a correct security model, but NARF adds domain hardware enforcement as a second independent layer. The justification is correct: capabilities are software-checked and rely on Rust's type system being sound plus `unsafe` blocks being audited; PKS/MTE catches violations even if a capability check is bypassed by a memory-corruption bug in TCB code. Neither layer alone survives a single critical bug in the other.

**16 domains is a hard ceiling.** PKS gives 16 supervisor keys; MTE gives 16 tags. The system design is constrained by this hardware limit at the domain level. This is load-bearing in a way the spec understates: 16 domains must accommodate all kernel subsystems, all driver classes, the tracer, the scheduler, and any future additions. The framekernel promise is that drivers run in their own domain — but with 16 total, a complex system (say, NVMe + network + GPU + virtio + USB) will exhaust domain space quickly if each driver instance gets its own domain. The spec needs a domain allocation policy before Stage 2.

**No root user, ever.** This is a philosophical commitment that cascades through the entire design. "No ambient authority" means every privilege must be traced to a specific capability derivation chain. Unlike Linux (where root can do anything) or even Fuchsia (which has root-equivalent jobs for system management), NARF has no escape hatch. This is the right security model for a fresh-start OS, but it has an operational cost: system administration requires a fully designed capability delegation protocol, which doesn't exist yet.

**Bootloader and firmware are trusted.** §2 takes this on faith. This is the correct pragmatic position (verifying the bootloader is a measured-boot problem, not a kernel problem), but the PKS whitepaper documents cases where firmware (SMM, UEFI runtime services) can subvert PKS by running in Ring -2/-1 without respecting supervisor keys. The trust boundary must explicitly exclude UEFI runtime services from post-boot operation, or the PKS domain isolation claim is hollow.

---

## Divergences from precedent

**vs. seL4:** seL4's security model is formally verified — the information-flow property (intransitive non-interference) is a proven theorem. NARF's security model is architecture-documented but not formally verified. The seL4-formal-verification research notes that proving capability integrity across async await points is a novel challenge seL4 didn't face; NARF's Rust type system helps (Owned<T> prevents capability duplication in safe code) but async suspension creates a gap: what happens to a capability that a Future holds across an await point if the Future is cancelled? If cancellation drops the Future without running cleanup, the capability leaks without revocation. This is a known async-Rust hazard and is not addressed in the security model.

**vs. Fuchsia Zircon:** Fuchsia separates userspace isolation (process address spaces) from kernel isolation (kernel is a monolith). NARF combines both: PKS/MTE isolates kernel components from each other (within a single address space), and userspace gets its own address-space separation plus user-PKU keys. This two-level isolation is more powerful than Fuchsia's one-level kernel isolation, but it means NARF must get both levels right. A bug in PKS domain-key assignment that leaks Ring-0 data between domains has no Ring-0 address-space boundary to stop it. Fuchsia's kernel bugs affect "the kernel" but not user processes directly; NARF's domain bugs can affect other driver domains.

**vs. Redox OS:** Redox runs all drivers as userspace processes in separate address spaces — simpler isolation model (hardware MMU), higher IPC overhead. NARF runs drivers as intra-kernel domains — same virtual address space, hardware-key isolation, lower IPC overhead. NARF's model is strictly more complex to get right. The "Capability Myths Demolished" paper argues capability correctness is independent of the isolation mechanism, but it was written for userspace processes, not intra-kernel domains. The composition rules in security-model §3 (capability ⊥ domain) need a written proof of why the two independent mechanisms don't create unexpected interaction when combined.

**vs. Linux with lockdown:** Linux's lockdown mode restricts what root can do, but root still exists and lockdown is advisory. NARF's no-root model is structural, not advisory. However, NARF also has no equivalent of Linux's mandatory access control (SELinux/AppArmor) for constraining what a legitimately-held capability can do beyond the type. A `Cap<Block, Write>` grants write access to any block device the block subsystem exposes — there is no domain-level or policy-level further restriction (e.g. "this process can only write to devices in sector range X"). seL4 addresses this via MLS labels; NARF has no equivalent.

---

## Proposed spec changes

- §4 Invariants: **Add: "The domain allocation policy is published in `memory/` §3 and enforced by `frame/`. No subsystem may claim a domain not assigned to it by the boot-time policy."** Currently the spec says 16 domains exist but never specifies who gets which. Why: without this, Stage 2 PKS implementation will have competing ad-hoc allocations across `memory/`, `tracing/`, `scheduler/`, and `drivers/` that are incompatible and impossible to audit.

- §3 Composition rules: **Define the threat model for a compromised domain N explicitly: what it can do, and what it cannot, using formal notation.** Currently "a compromised driver in domain N can affect domain N's data and its own capabilities; nothing else, modulo documented exceptions." What are the documented exceptions? At minimum: shared read-only memory (kernel image), shared clocksource, shared per-CPU executor state. Each exception is a hole in the domain isolation claim. Why: "modulo documented exceptions" that are never documented is equivalent to no claim at all.

- §5 Architecture notes (x86_64): **State explicitly that UEFI runtime services (EFI_RT_*) must be unmapped or called only before PKS is activated.** UEFI runtime services run in Ring 0 and do not respect supervisor protection keys — any call to them after PKS activation can read or overwrite domain-protected memory. Why: this is a real attack surface (firmware SMI handlers, UEFI variable services) documented in the PKS whitepaper and frequently missed by kernel developers.

- §8 Open questions: **Resolve "speculative side channels at domain boundary" before Stage 3** with an explicit policy statement. The answer should probably be: "NARF does not defend against speculative side channels within the same address space between domains; isolation at that level requires separate address spaces." Why: leaving this open implies the spec might later claim stronger guarantees than the hardware provides; committing to the weaker claim now prevents false security assurances in documentation.

- §4 Invariants: **Specify capability lifecycle under async Future cancellation.** A Future that holds a `Cap<T, R>` and is cancelled (dropped mid-flight) must either drop the cap (clean revocation) or transfer it back to the parent scope. Currently neither the security model nor the capabilities spec addresses this. Why: cap leaks via Future cancellation are the async-specific analogue of the "capability aliasing mid-transfer" pitfall flagged in the seL4 verification research.

- §7 Stage assignment: **Move threat-model-skeleton publication to Stage 1**, not Stage 2. Currently the skeleton is Stage 1 content but domain composition rules wait until Stage 2 (when PKS lands). However, Stage 1 already has the executor TCB — and threats against the executor are relevant before PKS exists. Why: publishing even a partial threat model at Stage 1 lets contributors evaluate security implications of early design decisions, rather than retroactively applying a Stage 2 threat model to Stage 1 code.

---

## Open invariants / cross-subsystem hazards

**security-model §4 (TCB boundary) ↔ scheduler §3.1 (spawn API):** `spawn<F>(f, domain)` takes a `DomainId` as a plain parameter. If this function is callable from any domain, the spawn itself is a privilege-escalation vector: a driver in domain 5 could spawn a task into domain 0 (TCB domain) if it somehow obtained the right `DomainId`. The security model says cap checks gate this, but §3 of `scheduler/` says capability checks are Stage 3. Before Stage 3, `spawn` into a foreign domain must be prohibited by an architectural invariant, not just deferred to future capability checks.

**security-model §4 (defence-in-depth) ↔ tracing §4 (TCB probe cap):** Tracing says "a probe on a TCB function requires a TCB-scoped install cap." But the security model says the TCB is `frame/`, `memory/` domain manager, `capabilities/` core, executor core. Probing these functions with `FnTime` would mean the tracer shadow stack (in the tracer domain) holds call-context information from the TCB domain — effectively, a cross-domain information channel. This is a designed-in covert channel that the security model should acknowledge explicitly and bound (e.g. "FnTime on TCB functions exposes call timing but not data contents; this is accepted").

**security-model §2 (assumptions) ↔ crypto §? (measured boot):** The security model assumes the bootloader is trusted without specifying how that trust is established. `crypto/` owns measured boot. If measured boot fails (e.g. a modified bootloader), the security model's entire foundation is invalid — but the kernel boots anyway, running in a compromised state. The security model needs an explicit "measured boot is a precondition for the threat model's guarantees" statement, with a reference to `crypto/`'s measured boot chain.

**security-model §4 (domain isolation) ↔ rcu §3.7 (domain-aware drops):** Reclamation runs in the owner's domain. But if a capability grants a cross-domain reader (domain M holds a `Shared<'g, T>` for data owned by domain N), the data is freed in domain N's context. If the `Drop` impl for the reclaimed object tries to revoke a cross-domain capability (e.g. zeroing a shared buffer), it does so with domain N's rights, which may not include write access to domain M's bookkeeping. The security model needs to specify whether cross-domain object ownership is permitted, and if so, what rights the reclamation context holds.

---

## Additional opinionated commentary

The biggest gap in the security model is the absence of an **information flow policy**. seL4 defines intransitive non-interference; Fuchsia has job hierarchy and capability attenuation rules. NARF has "a compromised driver in domain N can affect domain N's data and its own capabilities" — which is a confinement property, not an information-flow property. Confinement prevents escape; information flow prevents observation. A compromised domain N can still observe timing of operations in domain M (cache timing, interrupt latency, power consumption) without violating confinement. NARF explicitly defers speculative side channels, but covert channels through IPC timing or shared clocksource reads are not deferred — they're just not mentioned.

The "Rust type system is sound; unsafe blocks are audited" assumption is load-bearing and overly optimistic. Rust's type system is sound for the safe subset; `unsafe` in the TCB is audited by humans reviewing PRs. That review process produces two maintainers + security-review pass — adequate for a small team's careful work. But "audited" means "passed review at the time of writing," not "will remain correct as surrounding code changes." The security model needs a statement about how TCB soundness is maintained over time (e.g. Kani proofs on critical unsafe blocks), not just at the moment of submission.

The 16-domain ceiling deserves more architectural thought than it currently receives. A production system with full Stage 4 content — virtio block, net, gpu, plus the tracer domain, plus at least one user process domain, plus kernel/TCB — will hit 16 domains before all drivers are assigned. Either domains are shared (weakening isolation), or some drivers run in the same domain (weakening the "compromised driver affects only its domain" claim), or a domain multiplexing mechanism (context-switch domains, as some PKS research explores) is needed. This architectural question should be answered in Stage 2, not Stage 4.
