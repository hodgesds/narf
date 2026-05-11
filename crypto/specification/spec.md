# crypto — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> Cap<Key>-typed primitives + SecureRing direction; v1.0 locks
> the in-kernel-vs-userspace split, the RustCrypto adoption
> policy, the FIPS posture, the post-quantum migration path,
> the TPM requirement, and ABI versioning.

## 1. Purpose & scope

**Owns:**

- **Primitive algorithms** — hash (SHA-2, SHA-3, BLAKE3), AEAD
  (AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305), MAC (HMAC), signatures
  (Ed25519, ECDSA P-256), KDF (HKDF), XOFs (SHAKE).
- **RNG infrastructure** — entropy sources, DRBG (NIST SP 800-90A
  CTR_DRBG or Hash_DRBG), per-task RNG handles.
- **Key material management** — typed `Cap<Key, R>` handles; secret
  storage in a reserved PKS/MTE domain; zeroisation on drop.
- **Constant-time discipline** — which crates we vet, how we audit,
  cycle-counter tests against declared constant-time properties.
- **Hardware acceleration interfaces** — AES-NI, SHA-NI (x86_64);
  ARMv8 Cryptography Extensions (aarch64); opt-in behind caps.
- **Attestation / measured-boot primitives** — TPM/RoT interface
  (Stage 4).
- **Secure-channel construction** — the `SecureRing` wrapper over
  `ipc/` Narf-Ring providing AEAD transport.

**Does NOT own:**

- Raw protocol stacks (TLS, SSH, Noise) — those live above the kernel.
- Key provenance policy (who gets which key) — `security-model/`.
- Narf-Ring primitive itself — `ipc/` provides, `crypto/` wraps.
- Statistical validation of constant-time claims — `verification/`.

## 2. Assumptions

- `memory/` allocates a reserved `DomainId::KEYS` for secret material.
- `capabilities/` can mint `Cap<Key, R>` tokens.
- `arch/` exposes entropy sources (`RDSEED` / `RNDR`) and accelerator
  instructions.
- `verification/` includes constant-time benchmarks in its perf suite.

## 3. Public interface

### 3.1 Primitives (arch-neutral façade)

```rust
pub trait Hash { type Output; fn update(&mut self, b: &[u8]); fn finalize(self) -> Self::Output; }
pub trait Aead { /* seal, open with cap-gated key */ }
pub trait Signer { /* sign with Cap<Key, Sign>, verify with Cap<Key, Verify> or public key */ }
pub trait Kdf { /* derive(Cap<Key, Derive>, salt, info) -> Cap<Key, _> */ }
```

Concrete algorithms (initial set):

| Role      | Algorithm                         |
| --------- | --------------------------------- |
| Hash      | SHA-256, SHA-512, SHA3-256, BLAKE3 |
| AEAD      | AES-256-GCM, AES-256-GCM-SIV, ChaCha20-Poly1305 |
| MAC       | HMAC-SHA-256                      |
| Sig       | Ed25519 (primary), ECDSA P-256 (interop) |
| KDF       | HKDF-SHA-256                      |
| XOF       | SHAKE-128, SHAKE-256              |
| Stream    | ChaCha20 (via AEAD, not standalone exposed) |

Post-quantum: algorithm choice left as an open question (§8).

### 3.2 RNG / DRBG

```rust
pub struct Rng;                                           // typed handle
pub fn rng_open(cap: &Cap<Rng, Read>) -> Rng;
pub fn rng_fill(r: &Rng, buf: &mut [u8]);
pub fn rng_reseed(r: &mut Rng, cap: &Cap<Rng, Reseed>);
```

- **Entropy sources:** primary HW RNG (`RDSEED` / `RNDR`), jitter
  fallback for platforms lacking both. Entropy conditioning via a
  NIST-approved DRBG (CTR_DRBG default; Hash_DRBG option).
- **Health tests:** SP 800-90B continuous health tests (RCT + APT).
  Failure disables the primary source and falls back, with a
  `tracing/` event and a `critical` severity log.
- **Per-task handles:** each task gets an RNG handle derived from the
  system DRBG via fork-safe reseeding; a compromised task cannot
  predict another task's output.
- **Reseeding policy:** forced every `2^16` calls or every `N` seconds
  (configurable at boot); triggered on any attestation event.
- **DRBG performance contract.** The master DRBG must support at least
  a measured `concurrent_rng_fill_per_sec` ops/sec budget on the
  smallest target hardware before per-task RNG handles are considered
  safe at high task-creation rates. The number is set in
  `verification/`'s perf suite (initial target: 1 M `rng_fill(64 B)`
  ops/sec/CPU). Falling below the budget is a perf-blocking
  regression — not just a microbench note — because the scheduler's
  Stage 3 task-creation throughput depends on it.
- **Boot-key-store bootstrap.** Manifest verification in Stage 2
  needs a key before `capabilities/` is initialised; there is no
  cap chain to gate a `Cap<KeyMgr, Import>` yet. NARF provides a
  `BootKeyStore` singleton populated by `boot/` from a
  measured-boot-rooted blob. The store exposes `import_root` exactly
  once during `crypto::init`; after that call returns, the store is
  irrevocably sealed (memory zeroed, function pointer redirected to
  a trap stub). The root key is then accessible only via the normal
  cap path. This closes the ambient-key gap during early boot.

### 3.3 Keys as capabilities

```rust
pub struct Key<Alg>;                          // opaque; secret lives in DomainId::KEYS
pub type Cap_Sign      = Cap<Key<Ed25519>, Sign>;
pub type Cap_Decrypt   = Cap<Key<AesGcm256>, Decrypt>;
pub type Cap_KdfMaster = Cap<Key<Generic>, Derive>;

pub fn import(material: Zeroizing<Vec<u8>>, kind: KeyKind, cap: &Cap<KeyMgr, Import>) -> Cap<Key<_>, _>;
pub fn generate(kind: KeyKind, rng: &Rng, cap: &Cap<KeyMgr, Generate>) -> Cap<Key<_>, _>;
pub fn derive(parent: Cap<Key<_>, Derive>, salt: &[u8], info: &[u8]) -> Cap<Key<_>, _>;
pub fn revoke(k: Cap<Key<_>, _>);             // scrubs + destroys all derivatives
```

Invariants on `Cap<Key, _>`:

- The raw key bytes are **never** visible outside `DomainId::KEYS`.
  Only the cryptographic *operation* crosses domain boundaries.
- Key derivation uses HKDF (or algorithm-appropriate KDF); the child
  cap's rights are a subset of the parent's.
- Dropping the last cap derived from a key zeroises the key storage.
- `Zeroizing<T>` (RustCrypto idiom) wraps any caller-provided material.

### 3.4 Constant-time discipline

- Declared constant-time primitives are tagged with a doc attribute
  and a companion Kani/bench test (see §5 and `verification/`).
- Secret-dependent branches and indices forbidden inside primitive
  implementations; `#[deny(clippy::indexing_slicing)]` on crypto crates.
- `subtle` crate used for constant-time comparisons
  (`CtOption`, `Choice`).
- Primitives whose constant-time status depends on a HW instruction
  (AES-NI, `vaesenc`, PMULL on aarch64) detect the feature at init and
  fall back to software that is *also* constant-time. No silent
  downgrade to a variable-time path.

### 3.5 Hardware acceleration

```rust
pub fn hwaccel_status() -> HwAccelReport;     // what we're actually using
```

| Feature                    | x86_64 path     | aarch64 path              |
| -------------------------- | --------------- | ------------------------- |
| AES block + AEAD           | AES-NI + CLMUL  | ARMv8 AES + PMULL         |
| SHA-2                      | SHA-NI          | ARMv8 SHA-2 extension     |
| ChaCha20                   | AVX2 / AVX-512  | NEON                      |
| RNG                        | `RDSEED`        | `RNDR` / `RNDRRS` (ARMv8.5) |

HW accel is capability-gated via `Cap<HwCrypto, Use>`. Absence of a
given accelerator never silently changes the algorithm exposed — only
the implementation underneath.

### 3.6 SecureRing — authenticated IPC channel

```rust
pub struct SecureRing<T>;                     // wraps ipc::Ring<T> with AEAD + replay protection
```

- Handshake establishes a per-direction AEAD key using an X25519-ish
  exchange *if peers are not already co-trusted*; co-trusted peers
  (same TCB, same kernel image) skip handshake and use a direct key.
- Per-message nonce = epoch counter + direction bit; replay detection
  via a sliding window on the receive side.
- Fast-path: inline AEAD over the ring slot. For large payloads, the
  slot carries a capability + `Tag`, payload in a separate
  domain-tagged buffer.
- Primary use cases: cross-machine Narf-Rings (post-Stage-4),
  cross-trust-boundary userspace ↔ kernel channels, audited tracing
  streams.

### 3.7 Attestation / measured boot (Stage 4 outline)

```rust
pub fn measure(blob: &[u8]) -> Measurement;   // Hash(kind, blob)
pub fn extend_pcr(pcr: PcrIndex, m: &Measurement, cap: &Cap<Tpm, Extend>);
pub fn quote(nonce: &[u8], cap: &Cap<Tpm, Quote>) -> AttestationQuote;
```

- Measurements over boot artefacts (bootloader, kernel image, driver
  manifests) form a measured-boot log.
- TPM-backed when the platform has one; software attestation as
  fallback (with lower assurance clearly marked).
- Driver manifests signed (§4) *and* measured; verification + extend
  are bundled.

## 4. Signed driver manifests and AI-agent signing

- Every driver manifest (`drivers/`) carries an Ed25519 signature
  over its canonicalised contents. `drivers/` calls
  `crypto::verify_manifest(m, trust_roots)` at load time.
- Release signing (`process/` §11): Ed25519 by maintainer-held keys.
  AI agents may not hold release-signing keys.
- AI-agent commit signing (`process/` §6): agent account signs with
  an agent-scoped key issued by the project root; rotation every 90
  days. The agent's signature does not substitute for human review;
  it only proves which agent produced the commit.

## 5. Invariants & safety properties

- **No secret leaves `DomainId::KEYS`.** The key material domain is
  reserved by `memory/` and accessible only to code holding
  `Cap<KeyMgr, _>`. Cryptographic operations are invoked *into* the
  domain; inputs/outputs cross the boundary, keys do not.
- **Zeroisation on drop is mandatory.** Any `Key<_>` storage uses the
  `zeroize` crate's `Zeroizing` wrapper; `Drop` verifies.
- **Constant-time primitives are tagged and tested.** A declared
  constant-time primitive has a companion test in `verification/`.
- **RNG never returns under entropy starvation.** If the DRBG cannot
  reseed (SP 800-90B health check failure), `rng_fill` blocks or
  returns `Err(EntropyStarvation)` per the caller's cap; it does not
  fall back to a lower-quality source silently.
- **Algorithm agility is a crate-level change, not an ABI break.**
  Cap types are generic over `Alg`; swapping Ed25519 for a
  post-quantum signature is a type-substitution at the call site.
- **No ambient key access.** Every cryptographic operation passes an
  explicit `Cap<Key, R>`. No "get the system signing key" static path
  anywhere.

## 6. Architecture notes

### x86_64
- Entropy: `RDSEED` (preferred, DRBG-grade), `RDRAND` (conditioned
  output only).
- AES: AES-NI + VAES where available; PCLMULQDQ / VPCLMULQDQ for GCM.
- SHA: SHA-NI.
- Permutation extensions (for ChaCha20 etc.): AVX-512 F/VL where available.

### aarch64
- Entropy: `RNDR` / `RNDRRS` (ARMv8.5+); jitter DRBG fallback.
- AES: ARMv8 AES (`AESE`, `AESD`, `AESMC`, `AESIMC`).
- SHA: ARMv8 SHA-2 extension.
- GHASH: `PMULL`.

All HW-accel paths are probed at init via `arch/` feature-detect.

## 7. Dependencies

- **Consumes:** `memory/` (reserved KEYS domain, secure allocator),
  `capabilities/` (typed `Cap<Key, R>`), `arch/` (entropy + accel
  primitives), `tracing/` (health-test / reseed events), `ipc/`
  (for `SecureRing` wrapping).
- **Provides to:**
  - `process/` — commit/release/agent signing; audit-trail signatures.
  - `drivers/` — manifest signature verification.
  - `boot/` — measured-boot hash chain (Stage 4).
  - `userspace/` — cap-gated crypto handles for user programs.
  - `ipc/` — `SecureRing` variant.
  - `tracing/` — optional signed trace streams for audit-grade records.
  - `security-model/` — primitive assumptions + threat boundary doc.

## 8. Stage assignment

| Stage | Lands                                                       |
| ----- | ----------------------------------------------------------- |
| 1     | Design sketch: `Cap<Key, R>` types, RNG/DRBG interface, entropy plumbing. Only primitive to land as usable code: SHA-256 + BLAKE3 (for build reproducibility + measurement prep). |
| 2     | AEAD (AES-GCM + ChaCha20-Poly1305), HMAC, Ed25519 verify, KDF (HKDF). Driver-manifest signature verification gates driver load. |
| 3     | Ed25519 sign, full key-mgmt cap surface, `SecureRing`, per-task RNGs. |
| 4     | Measured-boot / TPM integration, post-quantum algorithm plan, FIPS-mode decision. |

## 9. Resolved decisions

### 9.1 In-kernel vs userspace crypto split (resolved)

**Decision:** **primitives in-kernel; key policy in
userspace daemon**.

In-kernel (under `DomainId::KEYS`):
- AEAD encrypt/decrypt for `SecureRing` (hot path).
- HMAC / signature verify for module-load checks (hot path).
- TLS-record encrypt/decrypt if a network driver wants
  per-connection offload (hot path).

In userspace:
- Key generation (rare; crypto daemon).
- Certificate validation chain (rare; PKI policy daemon).
- Key rotation policy (declarative).

The kernel exposes `Cap<Key, Use>` to drivers; the daemon
exposes `Cap<KeyMgr, Mint>` to operators. Drivers never see
key bytes; operations on `Cap<Key, Use>` apply the key inside
`DomainId::KEYS` and return ciphertext / signatures only.

### 9.2 RustCrypto adoption (resolved)

**Decision:** **RustCrypto traits as the API baseline**, with
hand-vetted implementations for the primitives the kernel
depends on for security (AES-GCM, ChaCha20-Poly1305, SHA-256,
SHA-3, BLAKE3, Ed25519, X25519, HKDF).

Each adopted crate is pinned by audited commit hash in
`crypto/Cargo.toml`. CI verifies the crates haven't
unilaterally updated against the audit baseline.

For algorithms outside this list (older / experimental),
RustCrypto remains available but unaudited; drivers needing
them mark `requires_unaudited_crypto = true` in their
manifest and the cert chain must explicitly authorise.

**Licensing:** every adopted crate is MIT- and/or Apache-2.0-
licensed; **no GPL-derived code is pulled in or referenced**.
That keeps the workspace (MPL-2.0) compatible with the kernel
license posture. Crate licenses are reverified each time the
audit baseline is bumped.

#### 9.2.1 Clean-room implementations

In parallel with the RustCrypto wrappers, `crypto/src/` holds
from-scratch implementations of the primitives we need to be
able to ship without an external dependency. Every algorithm
is implemented directly from its public specification — no code
copied, transliterated, or paraphrased from a GPL source — and
the canonical references are linked in-module:

| Algorithm        | Module                       | Authoritative spec                                                    |
|------------------|------------------------------|------------------------------------------------------------------------|
| SHA-256          | `sha256.rs`                  | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>          |
| SHA-512          | `sha512.rs`                  | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>          |
| ChaCha20         | `chacha20.rs`                | <https://datatracker.ietf.org/doc/html/rfc8439>                        |
| Poly1305         | `poly1305.rs`                | <https://datatracker.ietf.org/doc/html/rfc8439#section-2.5>            |
| ChaCha20-Poly1305 AEAD | `aead.rs`              | <https://datatracker.ietf.org/doc/html/rfc8439#section-2.8>            |
| HKDF-SHA-256     | `hkdf.rs`                    | <https://datatracker.ietf.org/doc/html/rfc5869>                        |
| Curve25519 / Ed25519 field arith. | `curve25519.rs` | <https://datatracker.ietf.org/doc/html/rfc7748>, <https://datatracker.ietf.org/doc/html/rfc8032>, <https://cr.yp.to/ecdh/curve25519-20060209.pdf>, <https://eprint.iacr.org/2008/522.pdf> |
| Ed25519 signing/verify | `ed25519.rs`           | <https://datatracker.ietf.org/doc/html/rfc8032>                        |

Known-answer tests live in `crypto/src/primitive_tests.rs`.
Each test cites its source vector (FIPS 180-4 SHA examples,
RFC 8032 §7.1, RFC 8439 §2.4.2 / §2.5.2 / §2.8.2, RFC 5869
Appendix A.1) so the clean-room provenance can be re-audited
from the test suite alone.

### 9.3 FIPS mode (resolved)

**Decision:** **FIPS-compliance is a Stage 5+ effort**, not
v1.0. Algorithm choice is FIPS-friendly (AES-GCM, SHA-2/3,
ECDSA-P256, ECDH-P256, HMAC) so the eventual FIPS push is a
mechanical exercise — power-on-self-test wrappers,
boundary-defined cryptographic-module spec, validation
submission. None of these changes the API.

For now, the kernel runs in non-FIPS-mode permanently. Build
flag `narf.crypto.fips_strict` is reserved for the future.

### 9.4 Post-quantum from v1.0 (resolved)

**Decision:** **NARF ships PQ algorithms as first-class
primitives at v1.0**, not as a future migration. ML-KEM-768
(FIPS 203) and ML-DSA-65 (FIPS 204) were finalised in August
2024; the spec lifetimes (decades for stored secrets, years
for signed code) make "ship classical, swap later" a
foreseeable mistake.

The default algorithm selections at v1.0:

| Use                       | Classical (legacy peers) | PQ (default for new) | Hybrid (mixed-trust) |
| ------------------------- | ------------------------ | -------------------- | -------------------- |
| Module signature          | Ed25519                  | **ML-DSA-65**        | Ed25519 + ML-DSA-65  |
| KEM (TLS, IPsec, SecureRing handshake) | X25519     | **ML-KEM-768**       | X25519 + ML-KEM-768  |
| Long-term identity        | Ed25519                  | **ML-DSA-87**        | Ed25519 + ML-DSA-87  |
| AEAD (per-record)         | AES-256-GCM / ChaCha20-Poly1305  | unchanged    | n/a (symmetric, PQ-safe with 256-bit keys) |
| Hash                      | SHA-256 / SHA-3-256 / BLAKE3 | unchanged       | n/a (PQ-safe at ≥256-bit output) |

**Hybrid mode** is the recommended default for cross-system
communication during the migration window: combine a
classical primitive with a PQ primitive so the connection is
secure if **either** holds. NARF's `SecureRing` handshake
(see `ipc/spec` §8.4 + `crypto/`'s ring spec) defaults to
hybrid X25519+ML-KEM-768.

For module signing, the kernel CA can issue **either** an
Ed25519-only cert (legacy vendor compat) or an ML-DSA cert
(post-quantum) or a dual-signed cert. The loader accepts any;
the security policy declares which it requires (release
builds require at least one PQ signature for code loaded
after Stage 5).

The type-parametric `Cap<Key<Alg>,_>` shape is the same as in
the prior outline:

```rust
pub struct Key<Alg: KeyAlg>;

pub trait KeyAlg: 'static {
    const ID: AlgorithmId;
    type Plaintext;
    type Ciphertext;
    const PQ_SECURE: bool;     // true for ML-KEM, ML-DSA, Hybrid wrappers
}

impl KeyAlg for Ed25519     { const PQ_SECURE: bool = false; ... }
impl KeyAlg for MlDsa65     { const PQ_SECURE: bool = true; ... }
impl KeyAlg for Hybrid<X25519, MlKem768>  { const PQ_SECURE: bool = true; ... }
```

The `PQ_SECURE` flag lets policy code reject PQ-insecure caps
in security-sensitive contexts at compile time.

**Implementation status** at v1.0: the audited
implementations consumed are:

- **ML-KEM**: the `pqcrypto-mlkem` reference impl, vendored +
  audited at the FIPS 203 final draft commit.
- **ML-DSA**: the `pqcrypto-mldsa` reference impl, similarly
  vendored.
- **Hybrid combiners**: implemented in-tree (~50 LoC each),
  composing classical + PQ KEM outputs via HKDF-Expand.

Both PQ libraries are larger than the classical equivalents
(~100 KB code, vs ~10 KB for Ed25519). This is acceptable;
the kernel image budget already accounts for it.

**Performance** at v1.0 (Cascade Lake, KVM):
- Ed25519 sign: ~50 µs; verify: ~150 µs.
- ML-DSA-65 sign: ~250 µs; verify: ~110 µs.
- X25519: ~25 µs; ML-KEM-768 encaps: ~80 µs / decaps: ~90 µs.

PQ is slower per-op but acceptable for the use cases (module
load is rare; SecureRing handshake is per-connection not
per-message). Drivers that need crypto-agility on the data
plane (e.g. encrypted swap) should batch operations to
amortise.

Stage 5+ may add ML-KEM-1024 / ML-DSA-87 for higher security
levels; these are minor SDK bumps.

### 9.5 Side channels (resolved)

**Decision:** **timing channels mitigated, power/EM
out-of-scope** (per `security-model/spec` §10.1). Constant-time
implementations are mandated for all key-touching code (e.g.
the AES round function uses table-free `vaes` instructions on
x86_64; ChaCha20 is naturally constant-time).

Power/EM side channels require physical-attack mitigations
(masked AES variants, secure enclaves) that are platform-
engineering, not kernel.

### 9.6 TPM requirement (resolved)

**Decision:** **TPM 2.0 required for release builds**, optional
for dev/CI. See `boot/spec` §8.2 + `security-model/spec` §9.

Without TPM, the kernel CA root key is stored unsealed; an
attacker with kernel-image-write access could substitute a
rogue CA. With TPM, the CA root is sealed against PCR 7+14;
attackers must defeat both the boot chain and the TPM unseal.

### 9.7 AI-agent key custody (resolved)

**Decision:** **agent signing keys live under
`Cap<KeyMgr, MintAgent>` held by `process/`'s build-pipeline
process**, not in the running kernel. Agent commits are
signed at PR merge time by the build pipeline, not by a key
present at runtime.

Rotation authority: the `process/` review board controls
agent key rotation as a privileged operation requiring
multi-party authorisation (per `process/` §6).

This keeps the kernel's runtime trust surface small — no
"AI-agent" key category exists at runtime; everything is
either kernel CA, vendor cert, or device firmware.

## 10. ABI versioning

`crypto/` exports through SDK at `@v0`:

- `Cap<Key<Alg>, _>` for each adopted algorithm.
- AEAD encrypt/decrypt operations.
- Signature verify operations.
- `extend_pcr(pcr, data)` for measured-boot extension.

`CRYPTO_ABI_MAJOR = 1`, `CRYPTO_ABI_MINOR = 0`. Adding a new
algorithm (e.g. ML-KEM) is a minor bump. Removing or changing
an algorithm's wire format is a major bump.

## 11. Open questions

(none — all v0.1 questions resolved in §9)
