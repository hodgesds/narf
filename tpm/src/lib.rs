#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_capabilities::{CapKind, CapType};

pub mod commands;
pub mod tpm2;
pub mod types;

pub use types::{PcrSet, PolicyHash, TpmError};

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

pub mod registry {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_lib::sync::IrqSafeSpinLock;

    static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn TpmDevice>>> = IrqSafeSpinLock::new(Vec::new());

    pub fn register(device: Arc<dyn TpmDevice>) {
        REGISTRY.lock().push(device);
    }

    pub fn list() -> Vec<Arc<dyn TpmDevice>> {
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
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct MockTpm {
        pcr_extensions: AtomicU32,
    }

    impl MockTpm {
        fn new() -> Self {
            Self {
                pcr_extensions: AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl TpmDevice for MockTpm {
        fn get_info(&self) -> TpmInfo {
            TpmInfo {
                manufacturer: 0x4D4F434B,
                version: 1,
                spec_level: 2,
            }
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
        narf_scheduler::__reset_queues_for_test();
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
        if success.load(Ordering::SeqCst) == 1 {
            TestResult::Pass
        } else {
            TestResult::Fail("get_random check failed")
        }
    }
    kernel_test_in!("tpm", smoke_tpm_get_random);

    fn smoke_tpm_pcr_extension() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = Arc::new(MockTpm::new());
        let m = mock.clone();
        narf_scheduler::spawn(async move {
            m.extend_pcr(0, &[0u8; 32])
                .await
                .expect("extend_pcr failed");
        });

        narf_scheduler::run_until_empty();
        if mock.pcr_extensions.load(Ordering::SeqCst) == 1 {
            TestResult::Pass
        } else {
            TestResult::Fail("pcr extension check failed")
        }
    }
    kernel_test_in!("tpm", smoke_tpm_pcr_extension);

    fn smoke_tpm_cap_kind() -> TestResult {
        use narf_capabilities::CapType;
        if matches!(TpmCapType::KIND, CapKind::Tpm) {
            TestResult::Pass
        } else {
            TestResult::Fail("cap kind mismatch")
        }
    }
    kernel_test_in!("tpm", smoke_tpm_cap_kind);

    // ── TPM 2.0 codec smokes ──────────────────────────────────────

    fn smoke_tpm2_header_round_trip() -> TestResult {
        use crate::tpm2::{Header, TPM_CC_STARTUP, TPM_ST_NO_SESSIONS};
        let h = Header {
            tag: TPM_ST_NO_SESSIONS,
            size: 12,
            code: TPM_CC_STARTUP,
        };
        let bytes = h.encode();
        if bytes[0..2] != 0x8001u16.to_be_bytes() {
            return TestResult::Fail("tag big-endian");
        }
        if bytes[2..6] != 12u32.to_be_bytes() {
            return TestResult::Fail("size big-endian");
        }
        let back = Header::decode(&bytes).expect("decode");
        if back != h {
            return TestResult::Fail("header round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm/tpm2", smoke_tpm2_header_round_trip);

    fn smoke_tpm2_header_rejects_invalid_tag() -> TestResult {
        use crate::tpm2::{Header, Tpm2Error};
        let mut buf = [0u8; 10];
        buf[0..2].copy_from_slice(&0xCAFEu16.to_be_bytes());
        match Header::decode(&buf) {
            Err(Tpm2Error::BadTag(0xCAFE)) => TestResult::Pass,
            _ => TestResult::Fail("non-TPM_ST tag must be rejected"),
        }
    }
    kernel_test_in!("tpm/tpm2", smoke_tpm2_header_rejects_invalid_tag);

    fn smoke_tpm2_startup_command() -> TestResult {
        use crate::tpm2::{startup, TPM_CC_STARTUP, TPM_ST_NO_SESSIONS, TPM_SU_CLEAR};
        let cmd = startup(TPM_SU_CLEAR);
        // Expected layout: tag (8001) | size (0x0C) | command (0x144) | TPM_SU (0x00)
        if cmd.len() != 12 {
            return TestResult::Fail("Startup command = 10 hdr + 2 SU = 12 bytes");
        }
        if u16::from_be_bytes([cmd[0], cmd[1]]) != TPM_ST_NO_SESSIONS {
            return TestResult::Fail("tag should be NO_SESSIONS");
        }
        if u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) != 12 {
            return TestResult::Fail("size field should be 12");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_STARTUP {
            return TestResult::Fail("command code should be Startup");
        }
        if u16::from_be_bytes([cmd[10], cmd[11]]) != TPM_SU_CLEAR {
            return TestResult::Fail("TPM_SU operand should be CLEAR (0)");
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm/tpm2", smoke_tpm2_startup_command);

    fn smoke_tpm2_get_random_command_layout() -> TestResult {
        use crate::tpm2::{get_random, TPM_CC_GET_RANDOM};
        let cmd = get_random(32);
        if cmd.len() != 12 {
            return TestResult::Fail("GetRandom = 10 hdr + 2 length = 12 bytes");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_GET_RANDOM {
            return TestResult::Fail("opcode mismatch");
        }
        if u16::from_be_bytes([cmd[10], cmd[11]]) != 32 {
            return TestResult::Fail("bytesRequested should round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm/tpm2", smoke_tpm2_get_random_command_layout);

    fn smoke_tpm2_get_capability_command_layout() -> TestResult {
        use crate::tpm2::{get_capability, TPM_CAP_PCRS, TPM_CC_GET_CAPABILITY};
        let cmd = get_capability(TPM_CAP_PCRS, 0, 8);
        // 10 hdr + 4 cap + 4 prop + 4 count = 22 bytes
        if cmd.len() != 22 {
            return TestResult::Fail("GetCapability = 22 bytes");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_GET_CAPABILITY {
            return TestResult::Fail("opcode mismatch");
        }
        if u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) != TPM_CAP_PCRS {
            return TestResult::Fail("capability field");
        }
        if u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]) != 8 {
            return TestResult::Fail("count field");
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm/tpm2", smoke_tpm2_get_capability_command_layout);

    fn smoke_tpm2_pcr_read_carries_selection_list() -> TestResult {
        use crate::tpm2::{pcr_read, TPM_ALG_SHA256, TPM_CC_PCR_READ};
        let cmd = pcr_read(TPM_ALG_SHA256, &[0x80, 0x00, 0x00]); // select PCR 7 only
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_PCR_READ {
            return TestResult::Fail("opcode");
        }
        // selection count
        if u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) != 1 {
            return TestResult::Fail("selection count = 1");
        }
        if u16::from_be_bytes([cmd[14], cmd[15]]) != TPM_ALG_SHA256 {
            return TestResult::Fail("hash alg should be SHA256");
        }
        if cmd[16] != 3 {
            return TestResult::Fail("size of select = bitmap byte count (3)");
        }
        if &cmd[17..20] != &[0x80, 0x00, 0x00] {
            return TestResult::Fail("PCR-select bitmap should round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm/tpm2", smoke_tpm2_pcr_read_carries_selection_list);

    fn smoke_tpm2_get_random_response_decode() -> TestResult {
        use crate::tpm2::parse_get_random_response;
        // body: 2-byte BE length=4 followed by 4 random bytes.
        let body = [0u8, 4, 0xAA, 0xBB, 0xCC, 0xDD];
        let bytes = parse_get_random_response(&body).expect("parse");
        if bytes != [0xAA, 0xBB, 0xCC, 0xDD] {
            return TestResult::Fail("random tail decode");
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm/tpm2", smoke_tpm2_get_random_response_decode);
}
