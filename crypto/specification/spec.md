# crypto — Specification

> Status: **Outline v0.1** (Stage 1 → 4).

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

## 9. Open questions

- **In-kernel vs userspace crypto daemon.** Framekernel purity says
  put non-hot-path crypto in a userspace domain; performance says
  keep AEAD in-kernel for `SecureRing`. The current design keeps
  both on the table: primitives live in the kernel behind a
  `DomainId::CRYPTO` domain; a userspace daemon is free to own key
  policy.
- **RustCrypto vs. vetted-vendor.** Use `RustCrypto` traits and
  selected implementations as the baseline; audit status per crate
  (see summaries). Replace individual crates where we find gaps.
- **FIPS mode.** Do we care pre-1.0? If yes, algorithm choice is
  narrowed and power-on self-tests are mandatory.
- **Post-quantum timeline.** ML-KEM + ML-DSA are the likely picks
  once standards stabilise. Design cap types so swapping is a
  type-level change.
- **Side channels beyond timing.** Power / EM side channels are
  out-of-scope for the kernel; we trust the platform. Document this
  in `security-model/`.
- **TPM requirement.** Mandate TPM 2.0 for Stage 4 measured boot, or
  accept software attestation as a parallel path?
- **AI-agent key custody.** Where do agent signing keys live, and who
  holds the rotation authority? (Ties to `process/` §6.)
