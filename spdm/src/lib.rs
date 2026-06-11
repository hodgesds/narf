#![no_std]

extern crate alloc;

pub mod handshake;
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

impl<'a> core::fmt::Debug for SpdmSession<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpdmSession")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
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
            } else if hdr.code == ResponseCode::Error as u8
                && hdr.param1 == ErrorCode::InvalidRequest as u8
            {
                break; // No more measurements
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
        narf_scheduler::__reset_queues_for_test();
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

    // ── Handshake-codec smokes ────────────────────────────────────

    fn smoke_spdm_get_version_pins_to_v10() -> TestResult {
        use crate::handshake::{build_get_version, REQ_GET_VERSION, SPDM_VERSION_10};
        let bytes = build_get_version();
        if bytes.len() != 4 {
            return TestResult::Fail("GET_VERSION = 4-byte header");
        }
        if bytes[0] != SPDM_VERSION_10 {
            return TestResult::Fail("GET_VERSION must be sent at SPDM 1.0 per §10.4");
        }
        if bytes[1] != REQ_GET_VERSION {
            return TestResult::Fail("opcode mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("spdm/handshake", smoke_spdm_get_version_pins_to_v10);

    fn smoke_spdm_version_response_round_trip() -> TestResult {
        use crate::handshake::{build_version_response, parse_version_response};
        let versions = [0x0010u16, 0x0011, 0x0012, 0x0013];
        let bytes = build_version_response(&versions);
        let parsed = parse_version_response(&bytes).expect("parse");
        if parsed != versions {
            return TestResult::Fail("VERSION list round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("spdm/handshake", smoke_spdm_version_response_round_trip);

    fn smoke_spdm_get_capabilities_v12_includes_size_fields() -> TestResult {
        use crate::handshake::{build_get_capabilities, SPDM_VERSION_12};
        let req = build_get_capabilities(SPDM_VERSION_12, 0x0A, 0xCAFE_BEEF);
        // 4 hdr + 8 (resv + ct + resv + flags) + 8 (transfer-size + max-msg) = 20.
        if req.len() != 20 {
            return TestResult::Fail("SPDM 1.2 GET_CAPABILITIES = 20 bytes");
        }
        let flags = u32::from_le_bytes([req[8], req[9], req[10], req[11]]);
        if flags != 0xCAFE_BEEF {
            return TestResult::Fail("flags should round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "spdm/handshake",
        smoke_spdm_get_capabilities_v12_includes_size_fields
    );

    fn smoke_spdm_negotiate_algorithms_length_field_self_consistent() -> TestResult {
        use crate::handshake::{
            build_negotiate_algorithms, ASYM_ECDSA_P384, HASH_SHA_384, REQ_NEGOTIATE_ALGORITHMS,
            SPDM_VERSION_12,
        };
        let req = build_negotiate_algorithms(SPDM_VERSION_12, 1, ASYM_ECDSA_P384, HASH_SHA_384);
        if req[1] != REQ_NEGOTIATE_ALGORITHMS {
            return TestResult::Fail("opcode mismatch");
        }
        let length = u16::from_le_bytes([req[4], req[5]]);
        if length as usize != req.len() {
            return TestResult::Fail("length field must equal byte count");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "spdm/handshake",
        smoke_spdm_negotiate_algorithms_length_field_self_consistent
    );

    fn smoke_spdm_get_certificate_layout() -> TestResult {
        use crate::handshake::{build_get_certificate, REQ_GET_CERTIFICATE, SPDM_VERSION_12};
        let req = build_get_certificate(SPDM_VERSION_12, 1, 0x40, 0x80);
        if req[1] != REQ_GET_CERTIFICATE {
            return TestResult::Fail("opcode mismatch");
        }
        if req[2] != 1 {
            return TestResult::Fail("slot id lives in Param1");
        }
        let offset = u16::from_le_bytes([req[4], req[5]]);
        let length = u16::from_le_bytes([req[6], req[7]]);
        if offset != 0x40 || length != 0x80 {
            return TestResult::Fail("offset/length operands wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("spdm/handshake", smoke_spdm_get_certificate_layout);

    fn smoke_spdm_certificate_response_parses() -> TestResult {
        use crate::handshake::{parse_certificate_response, RSP_CERTIFICATE, SPDM_VERSION_12};
        let mut buf = alloc::vec![SPDM_VERSION_12, RSP_CERTIFICATE, 0x02, 0];
        let portion: alloc::vec::Vec<u8> = (0..32u8).collect();
        buf.extend_from_slice(&(portion.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0x100u16.to_le_bytes()); // remainder
        buf.extend_from_slice(&portion);
        let (slot, plen, rem, body) = parse_certificate_response(&buf).expect("parse");
        if slot != 0x02 || plen != 32 || rem != 0x100 || body != portion {
            return TestResult::Fail("CERTIFICATE response decode");
        }
        TestResult::Pass
    }
    kernel_test_in!("spdm/handshake", smoke_spdm_certificate_response_parses);

    fn smoke_spdm_challenge_carries_nonce() -> TestResult {
        use crate::handshake::{build_challenge, REQ_CHALLENGE, SPDM_VERSION_12};
        let nonce = [0x42u8; 32];
        let req = build_challenge(SPDM_VERSION_12, 0, 1, &nonce);
        if req.len() != 36 {
            return TestResult::Fail("CHALLENGE = 4 hdr + 32 nonce");
        }
        if req[1] != REQ_CHALLENGE {
            return TestResult::Fail("opcode mismatch");
        }
        if req[4..36] != nonce {
            return TestResult::Fail("nonce should follow header");
        }
        if req[3] != 1 {
            return TestResult::Fail("measurement summary type lives in Param2");
        }
        TestResult::Pass
    }
    kernel_test_in!("spdm/handshake", smoke_spdm_challenge_carries_nonce);

    // ── deep spdm/messages coverage ──────────────────────────────────

    fn smoke_spdm_messages_header_encode_decode_round_trip() -> TestResult {
        use crate::messages::SpdmHeader;
        let h = SpdmHeader {
            version: 0x12,
            code: 0x84,
            param1: 0xAA,
            param2: 0xBB,
        };
        let mut buf = alloc::vec::Vec::new();
        h.encode(&mut buf);
        if buf.len() != 4 {
            return TestResult::Fail("header encode != 4 bytes");
        }
        if buf[0] != 0x12 || buf[1] != 0x84 || buf[2] != 0xAA || buf[3] != 0xBB {
            return TestResult::Fail("encoded header byte order drifted");
        }
        let d = SpdmHeader::decode(&buf).expect("decode");
        if d != h {
            return TestResult::Fail("decode didn't round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "spdm/messages",
        smoke_spdm_messages_header_encode_decode_round_trip
    );

    fn smoke_spdm_messages_header_short_buf_rejected() -> TestResult {
        use crate::messages::SpdmHeader;
        if SpdmHeader::decode(&[0u8; 3]).is_some() {
            return TestResult::Fail("3-byte buf should not decode");
        }
        if SpdmHeader::decode(&[0x12, 0x84, 0, 0]).is_none() {
            return TestResult::Fail("4-byte buf should decode");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "spdm/messages",
        smoke_spdm_messages_header_short_buf_rejected
    );

    fn smoke_spdm_messages_request_response_codes_distinct() -> TestResult {
        use crate::messages::{ErrorCode, RequestCode, ResponseCode};
        let reqs = [
            RequestCode::GetVersion as u8,
            RequestCode::GetCapabilities as u8,
            RequestCode::NegotiateAlgs as u8,
            RequestCode::GetMeasurements as u8,
        ];
        for (i, a) in reqs.iter().enumerate() {
            for (j, b) in reqs.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("RequestCode discriminants collapsed");
                }
            }
        }
        let rsps = [
            ResponseCode::Version as u8,
            ResponseCode::Capabilities as u8,
            ResponseCode::Algorithms as u8,
            ResponseCode::Measurements as u8,
            ResponseCode::Error as u8,
        ];
        for (i, a) in rsps.iter().enumerate() {
            for (j, b) in rsps.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("ResponseCode discriminants collapsed");
                }
            }
        }
        let errs = [
            ErrorCode::InvalidRequest as u8,
            ErrorCode::Busy as u8,
            ErrorCode::UnexpectedRequest as u8,
            ErrorCode::Unspecified as u8,
            ErrorCode::DecryptError as u8,
            ErrorCode::UnsupportedRequest as u8,
            ErrorCode::RequestResend as u8,
        ];
        for (i, a) in errs.iter().enumerate() {
            for (j, b) in errs.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("ErrorCode discriminants collapsed");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "spdm/messages",
        smoke_spdm_messages_request_response_codes_distinct
    );

    fn smoke_spdm_messages_get_capabilities_layout() -> TestResult {
        use crate::messages::GetCapabilitiesRequest;
        // 12-byte frame: 4-byte header + 1 reserved + 1 CT + 2 reserved
        // + 4 flags-LE.
        let buf = GetCapabilitiesRequest::encode(0x12);
        if buf.len() != 12 {
            return TestResult::Fail("GetCapabilities length != 12");
        }
        if buf[0] != 0x12 {
            return TestResult::Fail("version byte drifted");
        }
        if buf[1] != 0xE1 {
            return TestResult::Fail("code byte != REQ_GET_CAPABILITIES");
        }
        let flags = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if flags != 1 {
            return TestResult::Fail("flags != CERT_CAP=1");
        }
        TestResult::Pass
    }
    kernel_test_in!("spdm/messages", smoke_spdm_messages_get_capabilities_layout);

    fn smoke_spdm_messages_get_measurements_carries_zero_nonce() -> TestResult {
        use crate::messages::GetMeasurementsRequest;
        let buf = GetMeasurementsRequest::encode(0x12, 7);
        if buf.len() != 36 {
            return TestResult::Fail("GetMeasurements length != 36");
        }
        if buf[0] != 0x12 {
            return TestResult::Fail("version byte drifted");
        }
        if buf[3] != 7 {
            return TestResult::Fail("index should live in Param2");
        }
        if buf[4..36].iter().any(|&b| b != 0) {
            return TestResult::Fail("nonce should be zero-filled by encoder");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "spdm/messages",
        smoke_spdm_messages_get_measurements_carries_zero_nonce
    );

    fn smoke_spdm_messages_get_version_pins_to_v10() -> TestResult {
        // GET_VERSION must always carry version=0x10 per DSP0274; the
        // existing "spdm/handshake" test pins the handshake module's
        // encoder. This pins the messages-module encoder symmetric path.
        use crate::messages::GetVersionRequest;
        let buf = GetVersionRequest::encode();
        if buf.len() != 4 {
            return TestResult::Fail("GET_VERSION should be exactly 4 bytes");
        }
        if buf[0] != 0x10 {
            return TestResult::Fail("GET_VERSION must carry version 0x10");
        }
        if buf[1] != 0x84 {
            return TestResult::Fail("GET_VERSION code byte drifted");
        }
        TestResult::Pass
    }
    kernel_test_in!("spdm/messages", smoke_spdm_messages_get_version_pins_to_v10);

    // ── deep spdm/types coverage ─────────────────────────────────────

    fn smoke_spdm_types_error_variants_distinct() -> TestResult {
        use crate::types::SpdmError;
        use narf_tpm::TpmError;
        let all = [
            SpdmError::Transport,
            SpdmError::Protocol,
            SpdmError::Tpm(TpmError::NotPresent),
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("SpdmError variants collapsed");
                }
            }
        }
        if SpdmError::Tpm(TpmError::NotPresent) == SpdmError::Tpm(TpmError::HardwareError) {
            return TestResult::Fail("SpdmError::Tpm Eq ignored inner");
        }
        TestResult::Pass
    }
    kernel_test_in!("spdm/types", smoke_spdm_types_error_variants_distinct);
}
