#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_capabilities::{CapKind, CapType};
pub use narf_tpm::TpmError;

/// Capability type for SPDM attestation.
#[derive(Copy, Clone, Debug)]
pub struct SpdmCapType;

impl CapType for SpdmCapType {
    const KIND: CapKind = CapKind::Spdm;
}

#[derive(Debug, Clone)]
pub struct SpdmCaps {
    pub version: u16,
    pub capabilities: u32,
}

#[derive(Debug, Clone)]
pub struct Measurement {
    pub index: u8,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum SpdmError {
    Transport,
    Protocol,
    Tpm(TpmError),
}

/// Trait for devices that support SPDM attestation.
#[async_trait]
pub trait AttestationDevice: Send + Sync {
    /// Discovers SPDM capabilities.
    async fn discover(&self) -> Result<SpdmCaps, SpdmError>;

    /// Gets measurements from the device.
    async fn get_measurements(&self) -> Result<Vec<Measurement>, SpdmError>;
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct MockSpdmDevice {
        discovery_count: AtomicU32,
    }

    impl MockSpdmDevice {
        fn new() -> Self {
            Self {
                discovery_count: AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl AttestationDevice for MockSpdmDevice {
        async fn discover(&self) -> Result<SpdmCaps, SpdmError> {
            self.discovery_count.fetch_add(1, Ordering::SeqCst);
            Ok(SpdmCaps {
                version: 0x12,
                capabilities: 0x1,
            })
        }

        async fn get_measurements(&self) -> Result<Vec<Measurement>, SpdmError> {
            Ok(alloc::vec![Measurement {
                index: 1,
                data: alloc::vec![0xAA; 32]
            }])
        }
    }

    fn smoke_spdm_discovery() -> TestResult {
        narf_scheduler::init();
        let mock = Arc::new(MockSpdmDevice::new());
        let success = Arc::new(AtomicU32::new(0));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let caps = m.discover().await.expect("discovery failed");
            if caps.version == 0x12 {
                s.store(1, Ordering::SeqCst);
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) == 1 {
            TestResult::Pass
        } else {
            TestResult::Fail("SPDM discovery check failed")
        }
    }
    kernel_test_in!("spdm", smoke_spdm_discovery);

    fn smoke_spdm_cap_kind() -> TestResult {
        if matches!(SpdmCapType::KIND, CapKind::Spdm) {
            TestResult::Pass
        } else {
            TestResult::Fail("cap kind mismatch")
        }
    }
    kernel_test_in!("spdm", smoke_spdm_cap_kind);
}
