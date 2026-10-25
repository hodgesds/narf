# drivers/tpm — TPM 2.0 Extension Surface (not a production stack)

> **Composition (#934):** NARF has exactly one production TPM stack —
> the `tpm` protocol crate (`narf-tpm`: `TpmDevice` trait, registry,
> capability policy, canonical wire codec) plus the production CRB/TIS
> transport in `drivers/platform`, which probes hardware and registers
> the device `frame::measure` dispatches to. This crate is **not**
> linked into the boot path, owns no transport that runs, and must not
> grow a second trait, registry, or command encoding. Earlier versions
> of this README claimed the hardware role for this crate; that claim
> was the audit's finding, not the reality.

What this crate actually holds is staged, fixture-tested surface for
the follow-on lanes that compose it onto the canonical stack:

- **Extended command set** (`tpm2/`) — builders and parsers beyond the
  measured-boot minimum in `narf-tpm`: Create/Load/Unseal, NV
  define/read/write, key/object types (TPM2B_PUBLIC/PRIVATE, RSA and
  ECC P-256/P-384), the PCR bank/selection model, and NV-index
  management. Its `pcr_extend` (multi-bank, `TPM_ST_SESSIONS`) was the
  reference encoding for the #937 fix; the canonical single-digest
  builder now lives in `narf_tpm::commands`. Staged for #941/#944.
- **VFS bridges** (`devfs_bridge.rs`, `sysfs_bridge.rs`) — `/dev/tpm0`,
  `/dev/tpmrm0` and `/sys/class/tpm/tpm0/` implementations over an
  injected `TpmTransport`. Implemented and fixture-tested, instantiated
  never; publication is #940, which must wire them to the production
  transport rather than a second one.
- **Register-sequence models** (`crb.rs`, `tis.rs`) — the CRB/TIS
  register dances as free functions over mockable MMIO traits. The CRB
  file's PTP register map (buffer registers at 0x058…) is the map the
  production probe in `drivers/platform` converged onto in #939.
- **ACPI device identification** (`probe.rs`) — `MSFT0101`/`PNP0C31`
  HID matching and the TPM2 start-method vocabulary. TPM2 *table
  parsing* is owned by `narf-acpi` (`tpm2_info()` / `parse_tpm2`); the
  duplicate parser that lived here was deleted in #934. `MSFT0101`
  `_CRS` enumeration is a separable follow-up, not implemented here.

The crate is `no_std` with `alloc`, and depends on `narf-lib`,
`narf-filesystem`, and `narf-block` for the VFS bridges. The
`kernel-test` feature compiles the unit and end-to-end tests (including
the stateful `FakeTpmTransport` suite). Deferred work includes TPM 1.2
compatibility, EK/AK provisioning, the TSS2 userspace daemon protocol,
dynamic root-of-trust measurement, and interrupt-driven operation.
