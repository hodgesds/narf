//! narf-drivers-tpm — TPM 2.0 extension surface (NOT a production
//! stack).
//!
//! ## Composition status (#934)
//!
//! NARF has exactly one production TPM stack: `narf-tpm` (the
//! `TpmDevice` trait, registry, capability vocabulary, and the
//! canonical wire codec) plus the production CRB/TIS transport in
//! `drivers/platform`, which probes hardware, submits the frames
//! `narf-tpm` builds, and registers the device for
//! `frame::measure`. This crate must not grow a second trait,
//! registry, transport, or PCR_Extend encoding; its one linked
//! production consumer is narf-power's TPM custody anchor
//! (#1002), which composes onto the same codec + transport seam
//! from outside the boot path.
//!
//! What remains here is staged, fixture-tested surface for the
//! follow-on lanes that will compose it onto the canonical stack:
//! the extended command set (`tpm2/`: Create/Load/Unseal, NV,
//! object/PCR models — #941/#944), the devfs/sysfs bridges
//! (#940, over their own `TpmTransport` injection point), and the
//! CRB/TIS register-sequence models (`crb.rs` / `tis.rs`) whose
//! PTP register map the production probe converged onto (#939).
//! TPM2-table parsing is NOT here anymore: `narf_acpi` owns it
//! (see `probe.rs`).
//!
//! Attestation (#945) composes across all three owners rather
//! than living here: `narf-tpm` carries Quote + the TPMS_ATTEST
//! verifier, this crate carries the AK template + ReadPublic
//! builders the provisioning composition submits and the
//! `binary_bios_measurements` sysfs node (served from
//! `narf_tpm::attest`'s measurement hooks, not the transport),
//! and `drivers/platform` carries the provisioning + guarded
//! quote composition itself.
//!
//! Covers two host-interface flavours:
//!
//! - **CRB** (`crb.rs`) — Command/Response Buffer; the interface used
//!   by AMD/Intel firmware-TPMs (fTPM). ACPI device `MSFT0101`.
//!   Reference: TCG PC Client Platform TPM Profile (PTP) §6;
//!   Linux `drivers/char/tpm/tpm_crb.c`.
//!
//! - **TIS** (`tis.rs`) — TPM Interface Spec; the classic MMIO FIFO
//!   used by discrete LPC-attached chips (Infineon, Nuvoton, …).
//!   Reference: TCG PC Client Platform TPM Interface Spec 1.3;
//!   Linux `drivers/char/tpm/tpm_tis_core.c`.
//!
//! Both transports share the TPM 2.0 command set in `tpm2/`.
//!
//! ## Bring-up targets
//!
//! Zen 2 (Renoir/Lucienne) and Zen 4 Phoenix HawkPoint1 both expose
//! fTPM 2.0 via the CRB interface at the ACPI control-area address
//! from the TPM2 ACPI table.
//!
//! ## Deferred
//!
//! - TPM 1.2 compatibility
//! - EK certification / credential activation (MakeCredential /
//!   ActivateCredential): AK *provisioning* landed with #945; the
//!   EK-certificate chain that lets a remote party trust the AK
//!   belongs to a fleet-enrollment lane, not this surface
//! - TSS2 userspace daemon protocol
//! - DRTM (Dynamic Root of Trust Measurement)
//! - Interrupt-driven (polling-only today)

#![no_std]

extern crate alloc;

pub mod crb;
pub mod devfs_bridge;
#[cfg(feature = "kernel-test")]
pub mod e2e_tests;
/// Spec-shaped fixture TPM (#1002): a stateful command core
/// behind the [`devfs_bridge::TpmTransport`] seam — real
/// policyDigest chaining, real PCR/NV semantics — for the
/// suspend anchor's fixture suite and codec conversation tests.
/// Test surface only: compiled under `cfg(test)`, the
/// `kernel-test` harness, or the explicit `fixture-tpm`
/// feature a consumer's test suite forwards.
#[cfg(any(test, feature = "kernel-test", feature = "fixture-tpm"))]
pub mod fixture_tpm;
#[cfg(feature = "kernel-test")]
pub mod fixture_tpm_tests;
pub mod probe;
pub mod sysfs_bridge;
pub mod tests;
pub mod tis;
pub mod tpm2;
