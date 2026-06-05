//! narf-drivers-tpm — TPM 2.0 device drivers.
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
//! - EK / AK provisioning
//! - TSS2 userspace daemon protocol
//! - DRTM (Dynamic Root of Trust Measurement)
//! - Interrupt-driven (polling-only today)

#![no_std]

extern crate alloc;

pub mod crb;
pub mod devfs_bridge;
#[cfg(feature = "kernel-test")]
pub mod e2e_tests;
pub mod probe;
#[cfg(feature = "linux-compat")]
pub mod sysfs_bridge;
pub mod tests;
pub mod tis;
pub mod tpm2;
