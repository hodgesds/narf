# RustCrypto Audit Status — reading notes

**Primary sources:** the RustCrypto GitHub organisation README and
each crate's own `README.md` / `CHANGELOG.md`
(<https://github.com/RustCrypto>); NCC Group audit reports where
linked; `cargo-audit` advisory database
(<https://rustsec.org/advisories/>).

> Reading notes, not a complete audit register. Refresh before each
> stage gate; entries below reflect the view at the time of writing.

## Why this file exists

NARF standardises on the RustCrypto **trait** surface (`digest::Digest`,
`aead::AeadInPlace`, `signature::Signer`, …) because those traits are
stable, `no_std`-clean, and broadly implemented. The *implementations*
behind the traits vary in maturity, audit status, and
constant-time rigour. This file tracks what we consider production-
grade for NARF's TCB-adjacent use vs. "use with caveats" vs.
"re-implement or replace."

## Primitive-by-primitive quick take

| Primitive class | Crate              | Status for NARF                                   |
| --------------- | ------------------ | ------------------------------------------------- |
| SHA-2           | `sha2`             | Production. Widely deployed. HW-accel via `cpufeatures` dispatch. |
| SHA-3           | `sha3`             | Production. Stable, well-fuzzed.                  |
| BLAKE3          | `blake3` (official, not RustCrypto-org) | Production. Reference impl maintained by designers. |
| AES (raw block) | `aes`              | Production; CT software fallback + AES-NI path.   |
| AES-GCM         | `aes-gcm`          | Production; third-party audited (NCC). Prefer this over hand-rolled. |
| AES-GCM-SIV     | `aes-gcm-siv`      | Solid; check nonce-misuse resistance claims.      |
| ChaCha20-Poly1305 | `chacha20poly1305` | Production; widely deployed.                    |
| HMAC            | `hmac`             | Production; trivial wrapper over hash crates.     |
| HKDF            | `hkdf`             | Production.                                       |
| Ed25519         | `ed25519-dalek`    | Production; major audit history; prefer `v2` API. |
| ECDSA P-256     | `p256`             | Production; `ecdsa` crate + `p256` elliptic curve. Audit coverage is good. |
| X25519          | `x25519-dalek`     | Production.                                       |
| `subtle`        | `subtle`           | Mandatory — everything uses it for CT comparisons. |
| `zeroize`       | `zeroize`          | Mandatory — required for key drops per our spec.  |
| Post-quantum    | `ml-kem`, `ml-dsa` (RustCrypto) / `pqcrypto-*` | Early; track. Not for Stage 1–3. |

## NCC / third-party audits NARF should cite when adopting

- **`aes-gcm`** — audited by NCC Group (2022). Report linked from the
  crate's README. Findings were minor and remediated.
- **`ed25519-dalek`** — multiple audits over the years, most recent
  via the `curve25519-dalek` audit (Trail of Bits, 2023). Worth
  re-verifying that the current NARF-pinned version is at or above
  the audited revision.
- **`chacha20poly1305`** — constant-time properties tested via the
  RustCrypto project's own CT-test CI; no major external audit as of
  writing — flag as an open item for Stage 2.

## Ring vs. RustCrypto for hot paths

`ring` is an alternative for primitives where absolute performance
and audit maturity matter most (TLS-era deployments). Trade-offs for
NARF:

- `ring` is `std`-ish in places and has historically fought `no_std`;
  the assembly is audited more aggressively.
- RustCrypto is `no_std`-clean, modular, and algorithm-agile via
  traits — which NARF requires for post-quantum substitution.

Default: RustCrypto for everything that isn't demonstrably blocked by
performance; spot-use `ring` (or vetted-vendor assembly) where
benchmarks under `verification/` justify it.

## Constant-time claims to verify under NARF

Every algorithm NARF exposes as "constant-time" must have a test
under `verification/` that measures cycle-count variance against
secret inputs. Candidates for the first round:

- `aes-gcm` software path (no AES-NI).
- `ed25519-dalek` scalar multiplication.
- `subtle::ConstantTimeEq` for the `Key` comparison path.

## Things we will *not* rely on RustCrypto for

- **RNG / DRBG.** RustCrypto defers to `rand_core`. NARF needs a
  SP 800-90A-compliant DRBG with SP 800-90B health-checked entropy;
  this is NARF-owned code, not pulled from `rand_core::OsRng` (which
  has no DRBG semantics).
- **Measured-boot / TPM.** No RustCrypto equivalent; NARF interfaces
  directly to TPM 2.0 via its own transport.

## Hygiene checklist for each pulled crate

- [ ] Pinned by exact version in the workspace lockfile.
- [ ] Licence compatible with NARF's distribution model.
- [ ] `cargo-audit` clean at pin time; re-checked per release.
- [ ] No-default-features build works and produces the minimal surface.
- [ ] Constant-time test wired into `verification/` where claim is made.
- [ ] `unsafe` usage reviewed and documented.
