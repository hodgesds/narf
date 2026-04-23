# crypto — Design Notes

> Created: 2026-04-22

---

## Load-bearing decisions

**DomainId::KEYS is a singleton.** The spec says "secret material in a reserved PKS/MTE domain" but never asks whether there is one keys domain or many. Treating it as a singleton is the only coherent interpretation given that PKS gives you 15 non-TCB domains on x86_64 (one is the kernel). That means every driver, the filesystem, and the network stack all share the same key-material domain — distinct keys are co-resident. Domain isolation prevents reads from the wrong domain, but a bug in `memory/`'s key-domain management lets everything see everything. This is a much narrower blast radius than Linux, but not zero.

**RustCrypto algorithm agility is structural, not free.** The `Cap<Key<Alg>, R>` design means swapping Ed25519 → ML-DSA is a "type-level change." In practice, every call site that constructs or derives a `Cap<Key<Ed25519>, Sign>` must change. That is fine if the codebase is small; it is non-trivial once any protocol layer outside `crypto/` encodes the algorithm type. This assumption should be written down: *algorithm agility in NARF is source-level, not wire-level.* If protocol wire formats embed algorithm identifiers, that is a separate negotiation problem the spec does not address.

**DRBG is a NARF-owned implementation, not a crate dependency.** The research summary correctly calls this out — `rand_core::OsRng` has no DRBG semantics. But this means NARF is committing to writing and maintaining a SP 800-90A CTR_DRBG or Hash_DRBG from scratch in `no_std`. That is a significant auditing burden. The decision is correct but it should be flagged explicitly as: *we are now on the hook for a correct DRBG implementation, not just selecting one.*

**Constant-time is declared per-primitive and verified per-primitive.** The spec does not say who enforces this in CI or what the escalation is when a new hardware microarchitecture changes the timing properties of `vaesenc`. The assumption is that `verification/` runs ct-tests, but no gate prevents a contributor from adding a new hw-accel path that happens to have secret-dependent timing on one microarch.

---

## Divergences from precedent

**In-kernel AEAD for IPC vs. seL4/Fuchsia philosophy.** seL4 keeps all crypto outside the kernel; Fuchsia's kernel has no crypto either. NARF puts AEAD in-kernel for `SecureRing`. The justification — IPC performance — is reasonable, but it expands the TCB-adjacent surface. Every line of `chacha20poly1305` running in the crypto domain is code that, if it has a memory-safety bug, executes inside the address space that also holds `DomainId::KEYS`. The RustCrypto audit summary notes `chacha20poly1305` has *no major external audit as of writing* — this is a concrete risk, not theoretical.

**Per-task RNG fork-safety via derivation, not forking the CSPRNG state.** Linux forks the CSPRNG state on `fork()` (with AT_RANDOM). NARF re-derives per-task handles from the master DRBG via HKDF. This is cleaner cryptographically — no correlated outputs if two tasks are created from similar system state — but it means every task creation hits the master DRBG. At scale (many short-lived tasks), this becomes a bottleneck unless the DRBG is rate-tested under the Stage 3 `scheduler/` workload.

**Zeroisation on `Drop` via `zeroize`.** The `zeroize` crate relies on `write_volatile` to prevent the compiler from optimizing out stores, and `compiler_fence` to prevent reordering. This is correct in Rust today, but is not formally guaranteed by the language spec (there is no `volatile` semantic in Rust's memory model). HACL* and verified crypto implement zeroisation through assembly stubs for exactly this reason. For a system targeting Stage 4 FIPS consideration, `zeroize`-crate-based zeroisation should be treated as a strong convention, not a cryptographic guarantee, until the Rust memory model stabilises.

**No protocol-level crypto in-kernel.** Keeping TLS/SSH above the kernel is correct and aligned with Fuchsia. But it creates a bootstrap problem: during Stage 2, driver manifest verification uses Ed25519 signatures before `ipc/` or `capabilities/` are fully up. The key-loading path at manifest verify time is pre-capability, which means some ambient key access must exist during early boot. This is not addressed in §3.3.

---

## Proposed spec changes

- §3.2 RNG/DRBG: Add explicit performance contract — the master DRBG must support at least N concurrent `rng_fill` calls per second (N TBD under `verification/` benchmarks) before per-task RNG handles are considered safe at high task-creation rates. Without a measured bound, Stage 3 scheduler work may saturate the DRBG silently. — *prevents a latent performance cliff.*

- §3.3 Keys as capabilities (import): Clarify the pre-capability bootstrap path. `import()` requires `Cap<KeyMgr, Import>` — who holds that cap before `capabilities/` is initialised? Manifest verification in Stage 2 needs a key. Propose a `BootKeyStore` singleton (sealed at end of Stage 2 init) that provides the root trust anchor without a full cap chain, then is irrevocably consumed. — *closes the ambient-key gap during early boot.*

- §4 Signed driver manifests: Specify the trust root anchor format. An Ed25519 public key embedded where? In the kernel binary itself (measured by TPM)? In a separate manifest file? The spec says "trust roots" but never defines how they are loaded, by whom, and whether they are measured. — *load-bearing for the Stage 2 security model.*

- §5 Invariants: Add: "The crypto domain may not hold or modify any `Cap<Frame, _>` or any reference to `DomainId::TCB`." This parallels the driver invariant. Without it, a bug in an AEAD implementation in the crypto domain has a path to the TCB via the domain boundary — not via memory, but via a misdirected cap invocation. — *shrinks TCB blast radius.*

- §8 Stage assignment (Stage 1): SHA-256 + BLAKE3 land as "usable code." Specify whether these land in the crypto domain or in the TCB (pre-domain). If they land pre-domain-init they cannot use the `DomainId::KEYS` invariant, and any key material passed to them in Stage 1 is unprotected. The spec should say: Stage 1 crypto runs in the TCB with no domain protection; domain isolation for keys is a Stage 2 property. — *prevents false security assumptions in Stage 1 code.*

- §9 Open questions: Resolve the "in-kernel vs. userspace crypto daemon" question before Stage 3 begins, not after. The `SecureRing` implementation in Stage 3 will encode this choice structurally. If key policy moves to a userspace daemon post-Stage-3, `SecureRing` will need redesign. Pick a lane: primitives in-kernel behind `DomainId::CRYPTO`, policy daemon in userspace, with an explicit IPC protocol between them. — *avoids a Stage 3/4 interface flag-day.*

---

## Open invariants / cross-subsystem hazards

**`crypto/` ↔ `memory/` domain count.** PKS gives 16 domains, one of which is the kernel (PKRS key 0). Reserving `DomainId::KEYS` leaves 14 for drivers, tracing, filesystem, etc. If `DomainId::CRYPTO` is also reserved (for the AEAD fast-path suggested in §9), that is 13. The roadmap has: tracing domain, driver domains (multiple), filesystem domain, GPU domain. Thirteen fills fast. `memory/`'s domain allocation policy (`memory/ §...`) is unspecified — this is a cross-subsystem hazard where the first subsystem to claim a domain in Stage 2 code may inadvertently starve later stages. Needs a static domain allocation table in `memory/` spec.

**`crypto/` ↔ `rcu/` key revocation.** `revoke(Cap<Key<_>, _>)` scrubs and destroys all derivatives. If any in-flight `SecureRing` operation is mid-AEAD-computation using a derived key handle when revocation fires, the revocation either must wait for in-flight ops (requires tracking) or must destroy the key under a live computation (UB or panic). The spec says `revoke` "scrubs + destroys"; it does not specify what happens to concurrent users. The `rcu/` sleepable variant exists for exactly this pattern — cap revocation should gate on an RCU grace period — but `crypto/` §3.3 does not mention `rcu/`.

**`crypto/` ↔ `verification/` constant-time enforcement gap.** The spec lists three candidates for cycle-count variance tests (§3.4). But there is no mechanism preventing a future contributor from adding a new hw-accel path (e.g. AVX-512 VAES for AES-GCM) that is not on the ct-test list. Propose: any implementation tagged `#[constant_time]` must have a matching test entry in `verification/`'s suite at merge time — enforced by a CI check, not just policy.

---

## Additional opinionated commentary

The spec's handling of post-quantum is too deferral-comfortable. ML-KEM and ML-DSA were finalised in 2024 (FIPS 203/204). The `Cap<Key<Alg>>` type is designed to make swapping easy, but no timeline is named. For a system targeting Stage 4 measured boot with TPM attestation, a TPM that does not support ML-DSA-signed quote responses is already behind the curve for any deployment life past 2030. The algorithm plan should be *in the Stage 4 spec*, not perpetually deferred to "post-1.0".

The split between `ring` and RustCrypto is sensible, but the decision rule in the research summary ("use RustCrypto unless benchmarks in `verification/` say otherwise") has no feedback loop until `verification/` has benchmarks, which is Stage 1 at the earliest. In practice the default sticks. NARF should pre-commit to one specific RustCrypto version per primitive family in the Stage 2 manifest and treat switching to `ring` as an Interface-class change requiring two reviewers.
