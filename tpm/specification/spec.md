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
- The extended command set (Create/Load/Unseal, NV, object models) —
  staged, fixture-tested, and not production in `drivers/tpm` (see
  §3.4); it composes onto this crate's trait/registry when its
  lanes (#941/#944) land. The `/dev/tpm*` + `/sys/class/tpm`
  bridges, also in `drivers/tpm`, ARE production-composed onto the
  trait/registry since #940 (see §3.4).
- TPM2 ACPI table parsing — owned by `acpi/` (`tpm2_info()` /
  `parse_tpm2`); no TPM crate carries a second parser.

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

    /// Lifecycle: submit TPM2_Startup (provided; see below).
    async fn startup(&self, startup_type: StartupType) -> Result<(), TpmError>;

    /// Identity: query TPM2_GetCapability live (provided; §3.1).
    async fn query_info(&self) -> Result<TpmInfo, TpmError>;

    /// High-level GetRandom.
    async fn get_random(&self, bytes: u16) -> Result<Vec<u8>, TpmError>;
}
```

**Lifecycle (`startup`).** A powered-on TPM rejects every command
except `TPM2_Startup` with `TPM_RC_INITIALIZE` until one lands; the
trait owns the lifecycle edge so no conversation — production or
fixture — can begin without it. `startup` is a provided method:
it builds the frame with the canonical codec and submits through
`submit_raw`, so transports inherit it unchanged. `StartupType` is
the `TPM_SU` operand (`Clear` / `State`, Part 2 §6.9). The response
policy is Part 3 §9.3's: `TPM_RC_VALUE` from Startup means the
startup type did not match the TPM's state — the device was
already started, or a `State` startup found no saved state. The
trait folds both into the caller's goal state (`Clear` +
`TPM_RC_VALUE` ⇒ success; `State` + `TPM_RC_VALUE` ⇒ one retry as
`Clear`); every other response code propagates. The
Shutdown(STATE) → Startup(STATE) suspend/resume sequencing that
consumes the `State` form is owned by the power-suspend program
(#1003), not by this interface.

**Identity (`query_info`, #941).** `get_info` is the synchronous
cached read; `query_info` is the live query behind it. It is a
provided method: it builds `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES,
TPM_PT_FAMILY_INDICATOR, 64)` with the canonical codec, submits
through `submit_raw`, and parses the TPML_TAGGED_TPM_PROPERTY page
with the canonical parser (`ResponseParser::parse_get_capability_properties`;
the PCRS sibling parses TPML_PCR_SELECTION). The mapping is:
manufacturer ← `TPM_PT_MANUFACTURER` (required — its absence is a
`BadResponse`), version ← `TPM_PT_FIRMWARE_VERSION_1`, spec_level ←
`TPM_PT_REVISION` (both default 0 when unreported). The production
probe calls `query_info` once after Startup and caches the result;
on query failure the device still registers and `get_info` keeps
its unqueried defaults — identity is diagnostic, not a liveness
gate. Property tags live with the codec (`tpm2::TPM_PT_*`); note
`TPM_PT_PERMANENT` is in the variable group (0x200), while 0x10E in
the fixed group is `TPM_PT_HR_TRANSIENT_MIN`.

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

### 3.3 Device Registry

`registry` is the crate's composition point between transports and
consumers:

- `register(device: Arc<dyn TpmDevice>)` — called by the owning
  transport exactly once, at probe success, after `TPM2_Startup`
  (§3.1) has been submitted on the probed device: a registered
  device is a *started* device. The production transport is the
  platform probe (`drivers/platform` TPM driver, Stage::Subsys
  initcall); the registry itself never probes hardware.
- `list() -> Vec<Arc<dyn TpmDevice>>` — snapshot of the registered
  devices. `frame::measure` dispatches hardware PCR extends to the
  first registered device. An empty registry means measured boot
  records into its software shadow only, and boot reporting must say
  so — no hardware anchoring may be claimed.
- Registration is boot-lifetime: there is no production unregister.
  `__reset_for_test` (doc-hidden) exists for kernel-test fixtures
  only, so a fixture that registers a mock can restore the empty
  state for later tests.

### 3.4 Composition: one production stack (#934)

There is exactly one production TPM stack, and this section is its
contract:

- **Protocol/policy/codec — this crate (`narf-tpm`).** The
  `TpmDevice` trait, the registry, the capability vocabulary, and
  the canonical TPM 2.0 wire codec (`tpm2` header/constants +
  `commands` builder/parser). Every command frame submitted in
  production is built here — in particular `TPM2_PCR_Extend` exists
  exactly once: `commands::CommandBuilder::pcr_extend`
  (`TPM_ST_SESSIONS` + `TPM_RS_PW` session, §4).
- **Production transport — `drivers/platform`.** The CRB/TIS MMIO
  driver there is the only code that probes hardware, owns the
  probed-device singleton, and submits frames; on probe success it
  submits `TPM2_Startup(CLEAR)` (§3.1) and only then registers the
  device into this crate's registry (the §3.3 registry contract)
  for `frame::measure` to dispatch through — probe and Startup run
  at Stage::Subsys, measured boot at Stage::Late, so the first
  production extend always reaches a started TPM. A device that
  probed but would not start is not registered (its every command
  would fail with `TPM_RC_INITIALIZE`, and an unregistered device
  keeps the no-hardware-anchoring report honest).
  Its probe/discovery semantics (PTP register map, host-programmed
  CRB buffers, TPM2-table discovery via `narf_acpi::tpm2_info()`)
  are #939's.
- **`drivers/tpm` is not a stack.** It is an extension surface
  (extended command set, devfs/sysfs bridges, register models). It
  must not grow a second `TpmDevice` trait, registry, transport,
  TPM2-table parser, or PCR_Extend encoding; its lanes compose its
  modules onto the two owners above.
- **Userspace publication (#940).** On the same success path that
  registers the device (probe → `TPM2_Startup` → registry), the
  platform probe installs a synchronous `TpmTransport` over the
  registered device into `drivers/tpm`'s bridges and registers
  their surfaces: `/dev/tpm0` + `/dev/tpmrm0` (via
  `filesystem::register_tpm`) and `/sys/class/tpm/tpm0`. The
  transport is the bridges' only production implementation; it
  bridges sync→async with `block_on_spin` over `submit_raw` (the
  submit futures are self-waking register polls). The bridges keep
  no registry of their own — devfs writes and sysfs attribute reads
  alike submit through the installed transport, i.e. through the
  §3.3 registry device. Per-fd state (response slot; the RM node's
  transient-handle set, flushed with `TPM2_FlushContext` at close)
  rides the VFS clone-on-open hook (`FileOps::open_instance`): the
  registered nodes are prototypes, each `open(2)` gets a fresh
  instance, and the devfs proxies forward the hook to the
  installed delegate. Sysfs attributes that need capability data
  query per read through the transport. The command set they
  depend on (GetCapability) landed with #941: the canonical codec
  carries the builder and the property/PCR-selection parsers
  (§3.1), the keystone model serves the capability, and the
  attributes read live values against any device whose transport
  implements the command — including the model, whose identity
  (manufacturer "NARF", firmware 1.0, spec revision 159) the
  publication fixture now asserts live. The platform transport's
  `get_info` likewise answers from the probe-time `query_info`
  (§3.1) instead of the pre-#941 stub values, which remain only as
  the unqueried default.

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

The wire encoding is the canonical builder's
(`commands::CommandBuilder::pcr_extend`, TCG Part 3 §22.2):
`TPM_ST_SESSIONS` tag, the PCR handle, an authorization area of
size 9 carrying the empty password session (`TPM_RS_PW`, empty
nonce/HMAC), then `TPML_DIGEST_VALUES` (count 1, hashAlg SHA-256,
digest). The `TPM_ST_NO_SESSIONS` tag with a session area appended
— or with a zero authorizationSize — is malformed and a real TPM
rejects it with `TPM_RC_VALUE` (#937). Transports validate the
response (complete header, declared size within the buffer, zero
response code) and surface failures as typed errors, never as
silent success.

## 5. Security & Isolation

- **Driver Domain**: The raw TPM driver (TIS/CRB) runs in a dedicated PKS/MTE domain.
- **Kernel Bridge**: The `tpm/` crate acts as a bridge, verifying capabilities before delegating to the driver domain.
- **Hardware-Protected Secrets**: By using `TpmCap`, NARF ensures that even if the filesystem driver is compromised, it cannot unseal the disk encryption keys unless it also holds a `TpmCap` for the corresponding policy.

## 6. Stage Assignment

- **Stage 4 (now)**: Specification and initial `TpmDevice` trait.
- **Stage 5**: Support for PCR Extension and hierarchy management (Endorsement, Platform, Storage).
- **Stage 6**: RSA/ECC key generation and TPM-resident credentials.

## 7. Dependencies

- **Consumes**: `capabilities/`, `crypto/`, `lib/`, `scheduler/`.
- **Provides to**: `frame/` (measured boot, via the registry),
  `drivers/platform` (the production transport implements
  `TpmDevice` with this crate's builders), `block/` (encrypted
  storage seam), `spdm/` (error type + measurement feed).

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
- `ResponseParser::parse_get_capability_properties` /
  `parse_get_capability_pcr_selections` (#941) for the
  TPML_TAGGED_TPM_PROPERTY and TPML_PCR_SELECTION pages behind
  `query_info` (§3.1).
- `ResponseParser::parse_pcr_read` / `parse_pcr_read_full` (#1065)
  for TPM2_PCR_Read responses: the structural Part 3 §22.6 walk
  (UINT32 `pcrUpdateCounter`, TPML_PCR_SELECTION, TPML_DIGEST of
  TPM2B_DIGEST entries), returning the first digest or the full
  `PcrReadResponse`. No tail-read form exists.
- TPM_ST / TPM_CC / TPM_SU / TPM_ALG_ID / TPM_CAP / TPM_PT / TPM_RC constants.
