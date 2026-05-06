#![no_std]

extern crate alloc;

pub mod messages;
pub mod types;

use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;
use messages::{
    ErrorCode, GetCapabilitiesRequest, GetMeasurementsRequest, GetVersionRequest, ResponseCode,
    SpdmHeader,
};
use narf_capabilities::{CapKind, CapType};

pub use types::{Measurement, SpdmCaps, SpdmError};

/// Capability type for SPDM attestation.
#[derive(Copy, Clone, Debug)]
pub struct SpdmCapType;

impl CapType for SpdmCapType {
    const KIND: CapKind = CapKind::Spdm;
}

/// Trait for devices that support SPDM attestation.
#[async_trait]
pub trait AttestationDevice: Send + Sync {
    /// Performs a raw SPDM send/receive.
    async fn send_receive(&self, request: &[u8]) -> Result<Vec<u8>, SpdmError>;
}

/// A session manager for driving the SPDM protocol.
pub struct SpdmSession<'a> {
    device: &'a dyn AttestationDevice,
    version: u8,
}

impl<'a> SpdmSession<'a> {
    pub fn new(device: &'a dyn AttestationDevice) -> Self {
        Self {
            device,
            version: 0x10,
        }
    }

    /// Negotiates version, capabilities and algorithms.
    pub async fn establish(&mut self) -> Result<SpdmCaps, SpdmError> {
        // 1. GET_VERSION
        let req = GetVersionRequest::encode();
        let resp = self.device.send_receive(&req).await?;
        let hdr = SpdmHeader::decode(&resp).ok_or(SpdmError::Protocol)?;
        if hdr.code != ResponseCode::Version as u8 {
            return Err(SpdmError::Protocol);
        }

        // Extract version (simplified for Stage 4: assume 1.2 is supported)
        self.version = 0x12;

        // 2. GET_CAPABILITIES
        let req = GetCapabilitiesRequest::encode(self.version);
        let resp = self.device.send_receive(&req).await?;
        let hdr = SpdmHeader::decode(&resp).ok_or(SpdmError::Protocol)?;
        if hdr.code != ResponseCode::Capabilities as u8 {
            return Err(SpdmError::Protocol);
        }

        if resp.len() < 12 {
            return Err(SpdmError::Protocol);
        }
        let flags = u32::from_le_bytes([resp[8], resp[9], resp[10], resp[11]]);

        Ok(SpdmCaps {
            version: self.version as u16,
            capabilities: flags,
        })
    }

    /// Collects all measurements from the device.
    pub async fn collect_measurements(&self) -> Result<Vec<Measurement>, SpdmError> {
        let mut results = Vec::new();
        // Index 0xFE = all measurements (if supported) or 0x01..0x1F for individual
        for index in 1..=8 {
            let req = GetMeasurementsRequest::encode(self.version, index);
            let resp = self.device.send_receive(&req).await?;
            let hdr = SpdmHeader::decode(&resp).ok_or(SpdmError::Protocol)?;

            if hdr.code == ResponseCode::Measurements as u8 {
                results.push(Measurement {
                    index,
                    data: resp[10..].to_vec(),
                });
            } else if hdr.code == ResponseCode::Error as u8 {
                if hdr.param1 == ErrorCode::InvalidRequest as u8 {
                    break; // No more measurements
                }
            }
        }
        Ok(results)
    }
}

pub mod registry {
    use super::*;
    use alloc::sync::Arc;
    use narf_lib::sync::IrqSafeSpinLock;

    static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn AttestationDevice>>> =
        IrqSafeSpinLock::new(Vec::new());

    pub fn register(device: Arc<dyn AttestationDevice>) {
        REGISTRY.lock().push(device);
    }

    pub fn list() -> Vec<Arc<dyn AttestationDevice>> {
        REGISTRY.lock().clone()
    }
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct MockSpdm;

    #[async_trait]
    impl AttestationDevice for MockSpdm {
        async fn send_receive(&self, request: &[u8]) -> Result<Vec<u8>, SpdmError> {
            let hdr = SpdmHeader::decode(request).ok_or(SpdmError::Protocol)?;
            let mut resp = Vec::new();

            match hdr.code {
                0x84 => {
                    // GET_VERSION
                    SpdmHeader {
                        version: 0x10,
                        code: 0x04,
                        param1: 0,
                        param2: 0,
                    }
                    .encode(&mut resp);
                    resp.push(0); // Reserved
                    resp.push(1); // EntryCount
                    resp.extend_from_slice(&0x0012u16.to_le_bytes()); // SPDM 1.2
                }
                0xE1 => {
                    // GET_CAPABILITIES
                    SpdmHeader {
                        version: 0x12,
                        code: 0x61,
                        param1: 0,
                        param2: 0,
                    }
                    .encode(&mut resp);
                    resp.push(0);
                    resp.push(0); // CTExponent, Reserved
                    resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
                    resp.extend_from_slice(&0x00000001u32.to_le_bytes()); // Flags
                }
                0xE5 => {
                    // GET_MEASUREMENTS
                    if hdr.param2 == 1 {
                        SpdmHeader {
                            version: 0x12,
                            code: 0x65,
                            param1: 0,
                            param2: 0,
                        }
                        .encode(&mut resp);
                        resp.push(1); // NumberOfBlocks
                        resp.extend_from_slice(&[0x20, 0, 0]); // Length 32 (u24)
                        resp.extend_from_slice(&[0xAA; 32]); // Dummy measurement
                    } else {
                        SpdmHeader {
                            version: 0x12,
                            code: 0x7F,
                            param1: 0x01,
                            param2: 0,
                        }
                        .encode(&mut resp); // InvalidRequest
                    }
                }
                _ => return Err(SpdmError::Protocol),
            }
            Ok(resp)
        }
    }

    fn smoke_spdm_session_flow() -> TestResult {
        narf_scheduler::init();
        let success = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let s = success.clone();

        narf_scheduler::spawn(async move {
            let mock = MockSpdm;
            let mut session = SpdmSession::new(&mock);
            let caps = session.establish().await.expect("establish failed");
            if caps.version == 0x12 {
                let measurements = session
                    .collect_measurements()
                    .await
                    .expect("collect failed");
                if measurements.len() == 1 && measurements[0].data[0] == 0xAA {
                    s.store(true, core::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        narf_scheduler::run_until_empty();
        if success.load(core::sync::atomic::Ordering::SeqCst) {
            TestResult::Pass
        } else {
            TestResult::Fail("SPDM session flow failed")
        }
    }
    kernel_test_in!("spdm", smoke_spdm_session_flow);
}
