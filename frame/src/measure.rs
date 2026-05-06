//! Measured Boot Support — hardware-anchored TCB integrity.
//!
//! Spec: `frame/specification/spec.md` §3.7.
//! Anchors the NARF security model by measuring the boot chain into
//! the TPM's PCRs (Platform Configuration Registers).

extern crate alloc;

use alloc::vec::Vec;
use narf_crypto::blake3_hash;
use narf_tpm::TpmError;

/// Measured Boot Entry.
#[derive(Debug, Clone)]
pub struct Measurement {
    pub pcr: u32,
    pub digest: [u8; 32],
    pub label: &'static str,
}

static mut LOG: Vec<Measurement> = Vec::new();

/// Record a measurement in the global log and extend it into the TPM.
pub async fn measure(pcr: u32, label: &'static str, data: &[u8]) -> Result<(), TpmError> {
    let digest = blake3_hash(data);

    // SAFETY: Single-threaded boot path for now.
    unsafe {
        LOG.push(Measurement { pcr, digest, label });
    }

    // Try to extend into hardware TPM if available.
    // If not, we still have the software log for later attestation.
    if let Some(tpm) = narf_tpm::registry::list().first() {
        tpm.extend_pcr(pcr, &digest).await?;
    }

    Ok(())
}

/// Measure a physical memory range.
pub async fn measure_phys(
    pcr: u32,
    label: &'static str,
    phys: u64,
    len: u64,
) -> Result<(), TpmError> {
    // SAFETY: caller asserts range is identity-mapped readable.
    let slice = unsafe { core::slice::from_raw_parts(phys as *const u8, len as usize) };
    measure(pcr, label, slice).await
}

/// Returns a copy of the measurement log.
pub fn get_log() -> Vec<Measurement> {
    unsafe { LOG.clone() }
}
