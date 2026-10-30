# Fixed GPE wake ownership

## 1. Purpose and scope

Lease actual fixed-FADT GPE byte registers for a firmware-owned device wake
route while preserving ordinary SCI/AML dispatch and shared runtime enables.

## 2. Assumptions

Checksummed FADT discovery precedes use. The platform owns Power authority
and resolves the actual device `_PRW`; this register mechanism grants none.
No FADT reparse may race live wake leases.

## 3. Public interface

`GpeBlockInfo` retains address, total status-plus-enable length, first GPE,
GAS address-space ID, bit offset and access-size encoding. A nonzero extended
GAS overrides legacy fields. Byte-port consumers require System I/O, offset0,
access size unspecified/byte, a nonzero even byte count and a whole block
within the 16-bit port space. MMIO/unsupported GAS never becomes truncated
port I/O. Missing blocks are cleared by a later parse rather than inherited.

`gpe_wake::supported(number)` validates that one unambiguous actual block
covers the GPE. Wake leases currently admit GPE0–127, matching deferred SCI
ownership, and x86_64 only. `unsafe claim(number)` requires the current
platform Power invocation and its source-validated `_PRW`. It returns an
opaque `WakeGpe`. `enabled()` is the actual enable readback: false retains
ownership for cleanup and never authorizes sleep. `unsafe release(&mut token)`
requires the same current platform authority and exact token, restores the
runtime enable and verifies it. Failure retains the token.

`claim_with_prepare(number, prepare)` runs atomic observation reset under
exclusive CONTROL, after the Busy check and before ARMED/enable. A competing
claim never clears the existing owner's hit. `release_with_complete(token,
complete)` consumes old observations under the same CONTROL handoff after
terminal readback and before a successor may claim; inactive tokens never
run that callback. Callbacks must not allocate, block or re-enter GPE control.
An in-flight shared interrupt may conservatively wake a successor; no old
host cleanup may clear a successor's recorded event.

`armed(number)` and `any_armed(bits)` are atomic-only hard-IRQ queries. They
grant no authority and do not execute AML. `enable_gpe` uses the same enable
register serialization; a runtime enable requested while a lease exists
survives release. IRQ-safe GPE status read/clear functions retain their
existing behavior and reject unsupported GAS geometry.

The `kernel-test` feature supplies scoped RAM/W1C register fixtures. These
install no SCI, firmware route or Power grant and are absent from production.

## 4. Invariants

One wake lease owns a GPE at a time. Register read/modify/write preserves
neighboring bits. Already-enabled shared GPE status is never cleared by a
new claim; disabled stale status is acknowledged before enable. The armed
mask precedes enable, and cleanup clears it only after terminal readback.
Dropping a token never fabricates hardware cleanup; the power owner retains
it through failure. Unsupported or changed block identity causes no I/O.

## 5. Architecture

x86_64 byte-port FADT blocks are implemented. System-Memory GAS and aarch64
platform wake routes remain unsupported; no architecture fallback is assumed.

## 6. Dependencies

ACPI FADT, IRQ-safe byte-register serialization, actual SCI dispatch and the
power subsystem's explicit platform authority/retained route owner.

## 7. Stage assignment

Stage5 device wake infrastructure. Software fixtures do not qualify a board's
PME wiring or physical wake behavior.

## 8. Open questions

External GPE devices, PowerResource packages, MMIO GAS and aarch64 wake
delivery require their own source-backed owners. Native PCIe Root Port PME
service is a separate path requiring explicit bridge authority and IRQ setup.
