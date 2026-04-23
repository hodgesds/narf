# crypto — Research

## Primary sources

### Standards
- **NIST SP 800-90A Rev. 1 — DRBG constructions**.
  <https://csrc.nist.gov/pubs/sp/800/90/a/r1/final>
- **NIST SP 800-90B — Entropy Source Validation**.
  <https://csrc.nist.gov/pubs/sp/800/90/b/final>
- **NIST SP 800-90C (draft) — DRBG chain constructions**.
- **FIPS 197 (AES)**, **FIPS 180-4 (SHA-2)**, **FIPS 202 (SHA-3)**.
- **RFC 7748 — X25519 / X448**.  <https://datatracker.ietf.org/doc/html/rfc7748>
- **RFC 8032 — Ed25519 / Ed448**.  <https://datatracker.ietf.org/doc/html/rfc8032>
- **RFC 5869 — HKDF**.  <https://datatracker.ietf.org/doc/html/rfc5869>
- **RFC 9381 — VRF** (for future attestation schemes).

### Post-quantum
- **NIST FIPS 203 (ML-KEM)** and **FIPS 204 (ML-DSA)** — finalised 2024.
  <https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization>

### Hardware
- **Intel SDM Vol. 2 — AES-NI, SHA-NI, CLMUL, RDSEED, RDRAND instructions**.
- **Arm ARM — Cryptographic Extensions (AES, SHA-1, SHA-2, SHA-3)**.
- **TPM 2.0 Library Specification (TCG)**.
  <https://trustedcomputinggroup.org/resource/tpm-library-specification/>
- **DICE / RIoT attestation architecture (TCG)**.

### Side-channel references
- **Kocher (1996), "Timing Attacks on Implementations of
  Diffie-Hellman, RSA, DSS, and Other Systems"**.
- **Bernstein (2005), "Cache-timing attacks on AES"**.
- **"Lucky Thirteen" (AlFardan & Paterson, 2013)** — canonical timing
  side-channel case study.

## Secondary sources

- **RustCrypto project** — trait and impl source NARF defaults to.
  <https://github.com/RustCrypto>
- **`subtle` crate** — constant-time primitives (CtOption, Choice).
- **`zeroize` crate** — secret material zeroisation on drop.
- **`ring`** — mature vetted Rust crypto implementation (alternative
  to RustCrypto for specific primitives).
- **BoringSSL** — reference for algorithm-agnostic APIs and
  hardware-accel dispatch.
- **libsodium / NaCl** — reference for opinionated, hard-to-misuse API
  surface.
- **cryptol / HACL* / fiat-crypto** — formally-verified crypto
  implementations; candidates for Stage 4 replacement of selected
  hot primitives.
- **"Jasmin" and "Cryptol + SAW" tooling** — proof platforms for
  constant-time and functional correctness of crypto code.

## Distilled summaries

- [`summaries/rustcrypto-audit-status.md`](./summaries/rustcrypto-audit-status.md)
  — which RustCrypto crates have been third-party audited, which are
  widely deployed, which are flagged for NARF follow-up.
- (Future) `summaries/nist-sp-800-90a-drbg.md` — DRBG construction
  choice + SP 800-90B health-test requirements, to be added when
  Stage 1 RNG work begins.

## Open research questions

- **Implementation source per primitive.** RustCrypto vs. `ring` vs.
  in-tree port. Decide primitive-by-primitive based on audit status
  and constant-time review.
- **Post-quantum migration plan.** Algorithm agility at the cap-type
  level is designed in; the actual algorithm swap (Ed25519 → ML-DSA)
  needs a concrete timeline and key-rotation story.
- **Constant-time verification.** Can we use Jasmin/HACL*-derived code
  for AEAD, or is performance loss unacceptable?
- **TPM mandatory or optional for measured boot.** Drives Stage 4 scope.
- **Entropy in virtualised environments.** KVM guests may expose
  limited `RDSEED`; ensure jitter DRBG fallback quality is
  characterised.
- **Kernel vs. userspace split.** Primitives in-kernel for
  `SecureRing` speed; policy (who may sign what, key rotation) in a
  userspace daemon. Draw the line explicitly in Stage 3.
