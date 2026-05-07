# tpm — Specification

> Status: **v0.1** (Stage 4 design draft).
>
> High-level Trusted Platform Module (TPM 2.0) subsystem for the NARF ecosystem.
> Extends the basic driver logic with capability-gated access to PCRs,
> primary keys, and sealed storage.

## 1. Purpose & scope

**Owns:**
- The **TPM Interface Trait** (`TpmDevice`) for submitting raw and high-level commands.
- **TPM Capabilities** (`TpmCap<T, R>`) gating access to specific PCRs, NV indices, and key slots.
- **TPM2 Command Builder** — type-safe construction of TPM2 packets.
- **PCR Policy Engine** — validating and enforcing PCR-based authorization policies.

**Does NOT own:**
- Raw MMIO drivers (e.g., TIS/CRB) — these live in `drivers/platform/tpm`.
- Crypto primitives (HMAC, SHA-256) — consumed from `crypto/`.

## 2. Design Principles

1. **Principle of Least Privilege**: Access to the TPM is not global. A domain (e.g., a disk driver) is granted a `TpmCap` restricted to specific PCRs (e.g., PCR 0-7 for secure boot state).
2. **Async-First**: TPM operations are slow (often milliseconds). All high-level APIs are `async`.
3. **Clean-Room Library**: Implementation follows the official TCG TPM 2.0 Library Specification, without consulting non-free or GPL-licensed libraries (e.g., IBM's TSS or Linux's `tpm2-tss`).

## 3. Public Interface

### 3.1 Device Trait

```rust
#[async_trait]
pub trait TpmDevice: Send + Sync {
    /// Submit a raw TPM2 command.
    async fn submit_raw(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError>;

    /// High-level GetRandom.
    async fn get_random(&self, bytes: u16) -> Result<Vec<u8>, TpmError>;
}
```

### 3.2 TPM Capabilities

```rust
pub enum TpmRight {
    /// Allows extending a specific set of PCRs.
    Extend(PcrSet),
    /// Allows unsealing data restricted to a specific policy.
    Unseal(PolicyHash),
    /// Allows clearing the TPM (Owner privilege).
    Clear,
    /// Full administrative rights.
    Admin,
}

pub type Cap<TpmDevice, R> = ...;
```

## 4. Operation: PCR Extension

Extending a PCR is a foundational operation for Measured Boot.
```rust
pub async fn extend_pcr(
    cap: &Cap<TpmDevice, Extend(pcr_mask)>,
    pcr_index: u32,
    digest: [u8; 32],
) -> Result<(), TpmError>;
```
The kernel validates that `pcr_index` is included in the capability's `PcrSet` before submitting the command to the hardware.

## 5. Security & Isolation

- **Driver Domain**: The raw TPM driver (TIS/CRB) runs in a dedicated PKS/MTE domain.
- **Kernel Bridge**: The `tpm/` crate acts as a bridge, verifying capabilities before delegating to the driver domain.
- **Hardware-Protected Secrets**: By using `TpmCap`, NARF ensures that even if the filesystem driver is compromised, it cannot unseal the disk encryption keys unless it also holds a `TpmCap` for the corresponding policy.

## 6. Stage Assignment

- **Stage 4 (now)**: Specification and initial `TpmDevice` trait.
- **Stage 5**: Support for PCR Extension and hierarchy management (Endorsement, Platform, Storage).
- **Stage 6**: RSA/ECC key generation and TPM-resident credentials.

## 7. Dependencies

- **Consumes**: `drivers/`, `capabilities/`, `crypto/`, `lib/`.
- **Provides to**: Bootloader, Encrypted Storage, Identity Daemons.

## 8. Sources (public only) for the `tpm2` codec sub-module

`tpm2/` is a clean-room codec for the TPM 2.0 wire format that the
`commands/` module composes against. References (public-only):

- **TCG TPM Library Specification, Family 2.0, Level 00, Revision
  1.59** (Nov 2019) — Trusted Computing Group. Public.
  Part 1 §11.4 TPM_ST tag values, §17 Boot/Startup commands,
  §18.5 session authorization area.
  Part 2 §6 Constants — TPM_CC command codes, TPM_ALG_ID hash IDs,
  TPM_CAP capability identifiers, TPM_RC return codes.
  Part 3 §9 TPM2_Startup, §16 TPM2_GetRandom, §22 TPM2_PCR_Read /
  TPM2_PCR_Extend, §30 TPM2_GetCapability.

**No GPL Linux source consulted.** Surfaced:
- `Header::encode` / `Header::decode` (10-byte BE tag + size + code).
- `begin_command` + `finalise` for incremental command builders.
- Specific commands: `startup`, `shutdown`, `get_random`,
  `get_capability`, `pcr_read`.
- `parse_get_random_response` for the 2-byte BE length + bytes form.
- TPM_ST / TPM_CC / TPM_SU / TPM_ALG_ID / TPM_CAP / TPM_RC constants.
