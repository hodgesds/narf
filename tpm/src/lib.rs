#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use alloc::boxed::Box;
use async_trait::async_trait;
use narf_capabilities::{CapType, CapKind};

pub mod types;

pub use types::{TpmError, PcrSet, PolicyHash};

/// A specialized capability for TPM operations.
#[derive(Debug)]
pub enum TpmRight {
    /// Allows extending a specific set of PCRs.
    Extend(PcrSet),
    /// Allows unsealing data restricted to a specific policy.
    Unseal(PolicyHash),
    /// Allows reading PCR values.
    ReadPcr,
    /// Allows clearing the TPM (Owner privilege).
    Clear,
    /// Full administrative rights.
    Admin,
}

#[derive(Copy, Clone, Debug)]
pub struct TpmCapType;

impl CapType for TpmCapType {
    const KIND: CapKind = CapKind::Tpm;
}

/// A specialized TPM interface supporting TPM 2.0 operations.
#[async_trait]
pub trait TpmDevice: Send + Sync {
    /// Returns static information about the TPM.
    fn get_info(&self) -> TpmInfo;

    /// Submits a raw TPM2 command.
    async fn submit_raw(&self, cmd: &[u8]) -> Result<Vec<u8>, TpmError>;

    /// High-level GetRandom.
    async fn get_random(&self, bytes: u16) -> Result<Vec<u8>, TpmError>;

    /// Extends a PCR.
    async fn extend_pcr(&self, pcr: u32, digest: &[u8]) -> Result<(), TpmError>;

    /// Reads a PCR value.
    async fn read_pcr(&self, pcr: u32) -> Result<Vec<u8>, TpmError>;
}

#[derive(Debug, Clone, Copy)]
pub struct TpmInfo {
    pub manufacturer: u32,
    pub version: u32,
    pub spec_level: u32,
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use core::sync::atomic::{AtomicU32, Ordering};
    use alloc::sync::Arc;

    struct MockTpm {
        pcr_extensions: AtomicU32,
    }

    impl MockTpm {
        fn new() -> Self {
            Self { pcr_extensions: AtomicU32::new(0) }
        }
    }

    #[async_trait]
    impl TpmDevice for MockTpm {
        fn get_info(&self) -> TpmInfo {
            TpmInfo { manufacturer: 0x4D4F434B, version: 1, spec_level: 2 }
        }

        async fn submit_raw(&self, _cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
            Ok(alloc::vec![0; 10])
        }

        async fn get_random(&self, bytes: u16) -> Result<Vec<u8>, TpmError> {
            Ok(alloc::vec![0xAA; bytes as usize])
        }

        async fn extend_pcr(&self, _pcr: u32, _digest: &[u8]) -> Result<(), TpmError> {
            self.pcr_extensions.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn read_pcr(&self, _pcr: u32) -> Result<Vec<u8>, TpmError> {
            Ok(alloc::vec![0; 32])
        }
    }

    fn smoke_tpm_get_random() -> TestResult {
        narf_scheduler::init();
        let mock = Arc::new(MockTpm::new());
        let success = Arc::new(AtomicU32::new(0));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let res = m.get_random(16).await.expect("get_random failed");
            if res.len() == 16 && res[0] == 0xAA {
                s.store(1, Ordering::SeqCst);
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) == 1 { TestResult::Pass }
        else { TestResult::Fail("get_random check failed") }
    }
    kernel_test_in!("tpm", smoke_tpm_get_random);

    fn smoke_tpm_pcr_extension() -> TestResult {
        narf_scheduler::init();
        let mock = Arc::new(MockTpm::new());
        let m = mock.clone();
        narf_scheduler::spawn(async move {
            m.extend_pcr(0, &[0u8; 32]).await.expect("extend_pcr failed");
        });

        narf_scheduler::run_until_empty();
        if mock.pcr_extensions.load(Ordering::SeqCst) == 1 { TestResult::Pass }
        else { TestResult::Fail("pcr extension check failed") }
    }
    kernel_test_in!("tpm", smoke_tpm_pcr_extension);

    fn smoke_tpm_cap_kind() -> TestResult {
        use narf_capabilities::CapType;
        if matches!(TpmCapType::KIND, CapKind::Tpm) { TestResult::Pass }
        else { TestResult::Fail("cap kind mismatch") }
    }
    kernel_test_in!("tpm", smoke_tpm_cap_kind);
}
