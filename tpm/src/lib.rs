//! narf-tpm — the canonical TPM 2.0 protocol crate (composition,
//! #934).
//!
//! This crate is the single protocol/policy surface for TPM in
//! NARF: the `TpmDevice` trait, the device `registry` that
//! `frame::measure` dispatches through, the capability vocabulary
//! (`TpmRight`), and the canonical TPM 2.0 wire codec (`tpm2` +
//! `commands`). The sole production transport — the CRB/TIS MMIO
//! driver that probes hardware and registers a device here — lives
//! in `drivers/platform` (`drivers/platform/src/tpm.rs`). There is
//! no second registry, trait, or PCR_Extend encoding: transports
//! submit frames built by this crate's builders, and consumers
//! look devices up only through `registry`.

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

    /// Test-only: drop every registered device, restoring the
    /// no-TPM state a TPM-less boot observes. Production
    /// registration is boot-lifetime (the platform probe registers
    /// once, at Stage::Subsys); fixtures that register a mock must
    /// call this on exit so later smokes are not dispatched to it.
    #[doc(hidden)]
    pub fn __reset_for_test() {
        REGISTRY.lock().clear();
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

    fn smoke_tpm_registry_register_list_and_reset() -> TestResult {
        // The registry is the composition point the measured-boot
        // dispatch consults: registration must make the exact device
        // visible to list(), and the test reset must restore the
        // empty state. Reset on entry AND exit — the registry is
        // global, and a leaked mock would silently become the
        // dispatch target for later smokes.
        registry::__reset_for_test();
        if !registry::list().is_empty() {
            return TestResult::Fail("registry not empty after reset");
        }
        let mock: Arc<dyn TpmDevice> = Arc::new(MockTpm::new());
        registry::register(mock.clone());
        let list = registry::list();
        if list.len() != 1 || !Arc::ptr_eq(&list[0], &mock) {
            registry::__reset_for_test();
            return TestResult::Fail("registered device not returned by list()");
        }
        registry::__reset_for_test();
        if !registry::list().is_empty() {
            return TestResult::Fail("registry not empty after final reset");
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm", smoke_tpm_registry_register_list_and_reset);

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
        if cmd[17..20] != [0x80, 0x00, 0x00] {
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

    // ── deep tpm/commands coverage ────────────────────────────────────
    //
    // `commands::CommandBuilder` + `ResponseParser` build / parse TPM2
    // wire frames. The fields are big-endian per TCG Part 1 §17.

    fn smoke_tpm_command_builder_writes_size_in_header() -> TestResult {
        use crate::commands::{CommandBuilder, CommandCode};
        // After finish(), bytes 2..6 contain the total command length
        // in big-endian. Build the smallest possible cmd (GetRandom
        // with bytes=0 produces 12 bytes: 10-byte hdr + 2-byte param).
        let buf = CommandBuilder::get_random(0);
        if buf.len() != 12 {
            return TestResult::Fail("GetRandom(0) command length drifted from 12");
        }
        let size = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        if size as usize != buf.len() {
            return TestResult::Fail("encoded size doesn't match Vec length");
        }
        // Tag = TPM_ST_NO_SESSIONS (0x8001).
        if u16::from_be_bytes([buf[0], buf[1]]) != crate::commands::TPM_ST_NO_SESSIONS {
            return TestResult::Fail("tag != TPM_ST_NO_SESSIONS");
        }
        // CC = GetRandom (0x0000_017B).
        if u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]) != CommandCode::GetRandom as u32 {
            return TestResult::Fail("cc != GetRandom");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "tpm/commands",
        smoke_tpm_command_builder_writes_size_in_header
    );

    fn smoke_tpm_command_builder_pcr_read_encodes_selection() -> TestResult {
        use crate::commands::{CommandBuilder, CommandCode};
        // PCR_Read for PCR 7: selection mask byte 0 = 1 << 7 = 0x80.
        let buf = CommandBuilder::pcr_read(7);
        // Body starts at offset 10: count(u32) hashAlg(u16) sizeof(u8) mask(3)
        // total body = 4 + 2 + 1 + 3 = 10 ⇒ command length = 20.
        if buf.len() != 20 {
            return TestResult::Fail("pcr_read length drifted from 20");
        }
        if u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]) != CommandCode::PcrRead as u32 {
            return TestResult::Fail("cc != PcrRead");
        }
        // count == 1
        if u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]) != 1 {
            return TestResult::Fail("count != 1");
        }
        // hashAlg == 0x000B (SHA256)
        if u16::from_be_bytes([buf[14], buf[15]]) != crate::tpm2::TPM_ALG_SHA256 {
            return TestResult::Fail("hashAlg != SHA256");
        }
        // sizeofSelect == 3
        if buf[16] != 3 {
            return TestResult::Fail("sizeofSelect != 3");
        }
        // mask: byte 0 bit 7 set
        if buf[17] != 0x80 || buf[18] != 0 || buf[19] != 0 {
            return TestResult::Fail("PCR 7 selection mask wrong");
        }
        // PCR 16 → mask byte 2 bit 0.
        let buf16 = CommandBuilder::pcr_read(16);
        if buf16[17] != 0 || buf16[18] != 0 || buf16[19] != 1 {
            return TestResult::Fail("PCR 16 selection mask wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "tpm/commands",
        smoke_tpm_command_builder_pcr_read_encodes_selection
    );

    fn smoke_tpm_command_builder_pcr_extend_carries_digest() -> TestResult {
        use crate::commands::{CommandBuilder, CommandCode};
        let digest = [0xA5u8; 32];
        let buf = CommandBuilder::pcr_extend(3, &digest);
        // Header (10) + pcrHandle (4) + authSize (4) + auth (9) +
        // count (4) + hashAlg (2) + digest (32) = 65.
        if buf.len() != 65 {
            return TestResult::Fail("pcr_extend length drifted from 65");
        }
        if u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]) != CommandCode::PcrExtend as u32 {
            return TestResult::Fail("cc != PcrExtend");
        }
        // Tag = TPM_ST_SESSIONS (0x8002). pcrHandle is an
        // authorization handle: under TPM_ST_NO_SESSIONS the TPM
        // parses the authorizationSize as the digest count and
        // rejects the frame (#937). This assertion is the one whose
        // absence let the malformed encoding pass its own fixture.
        if u16::from_be_bytes([buf[0], buf[1]]) != crate::commands::TPM_ST_SESSIONS {
            return TestResult::Fail("tag != TPM_ST_SESSIONS");
        }
        // pcrHandle BE u32 at body[0..4]
        if u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]) != 3 {
            return TestResult::Fail("pcrHandle != 3");
        }
        // authSize == 9
        if u32::from_be_bytes([buf[14], buf[15], buf[16], buf[17]]) != 9 {
            return TestResult::Fail("authSize != 9");
        }
        // TPM_RS_PW handle 0x4000_0009
        if u32::from_be_bytes([buf[18], buf[19], buf[20], buf[21]]) != 0x4000_0009 {
            return TestResult::Fail("session handle != TPM_RS_PW");
        }
        // hashAlg = SHA256 at body offset 23..25 (after count u32)
        // body starts at 10; pcrHandle(4)+authSize(4)+auth(9)+count(4) = 21
        // so hashAlg lives at 10+21 = 31.
        if u16::from_be_bytes([buf[31], buf[32]]) != crate::tpm2::TPM_ALG_SHA256 {
            return TestResult::Fail("hashAlg != SHA256");
        }
        // Digest at 33..65.
        if &buf[33..65] != digest.as_slice() {
            return TestResult::Fail("digest tail wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "tpm/commands",
        smoke_tpm_command_builder_pcr_extend_carries_digest
    );

    fn smoke_tpm_command_builder_pcr_extend_exact_bytes() -> TestResult {
        use crate::commands::CommandBuilder;
        // PCR 4 (the measured-boot PCR) + a digest of distinct bytes
        // so any transposition in the frame shows up in the diff.
        let digest: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let buf = CommandBuilder::pcr_extend(4, &digest);
        // The full frame, laid out by hand per TPM 2.0 Part 3 §22.2 —
        // byte-identical in structure to the reference encoding in
        // drivers/tpm/src/tpm2/commands.rs::pcr_extend:
        //   tag TPM_ST_SESSIONS, TPM_RS_PW session (authSize 9),
        //   TPML_DIGEST_VALUES { count 1, { SHA256, digest } }.
        let expected: [u8; 65] = [
            0x80, 0x02, // tag = TPM_ST_SESSIONS
            0x00, 0x00, 0x00, 0x41, // commandSize = 65
            0x00, 0x00, 0x01, 0x82, // cc = TPM_CC_PCR_Extend
            0x00, 0x00, 0x00, 0x04, // pcrHandle = 4
            0x00, 0x00, 0x00, 0x09, // authorizationSize = 9
            0x40, 0x00, 0x00, 0x09, // sessionHandle = TPM_RS_PW
            0x00, 0x00, // nonceSize = 0
            0x00, // sessionAttributes = 0
            0x00, 0x00, // hmacSize = 0
            0x00, 0x00, 0x00, 0x01, // TPML_DIGEST_VALUES.count = 1
            0x00, 0x0B, // hashAlg = TPM_ALG_SHA256
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, // digest
        ];
        if buf.as_slice() != expected.as_slice() {
            return TestResult::Fail("pcr_extend frame != reference encoding");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "tpm/commands",
        smoke_tpm_command_builder_pcr_extend_exact_bytes
    );

    fn smoke_tpm_pcr_extend_response_rejects_truncated_and_error_rc() -> TestResult {
        use crate::commands::ResponseParser;
        use crate::types::{TpmError, TpmRc};
        // Negative fixture (#937): a malformed/truncated extend
        // response must fail clean with a typed error, never panic
        // and never be accepted as success.
        // (a) Empty and header-truncated responses.
        for short in [&[][..], &[0x80u8, 0x02][..], &[0u8; 9][..]] {
            match ResponseParser::new(short) {
                Err(TpmError::BadResponse) => {}
                _ => return TestResult::Fail("truncated extend response not BadResponse"),
            }
        }
        // (b) A well-framed header carrying TPM_RC_VALUE (0x184 —
        // the exact rejection a real TPM returned for the old
        // malformed encoding) maps to Rc(Value), not Ok.
        let mut err_resp = [0u8; 10];
        err_resp[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
        err_resp[2..6].copy_from_slice(&10u32.to_be_bytes());
        err_resp[6..10].copy_from_slice(&0x184u32.to_be_bytes());
        match ResponseParser::new(&err_resp) {
            Err(TpmError::Rc(TpmRc::Value)) => {}
            _ => return TestResult::Fail("TPM_RC_VALUE extend response not Rc(Value)"),
        }
        // (c) A success header (RC 0) is accepted.
        let mut ok_resp = [0u8; 10];
        ok_resp[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
        ok_resp[2..6].copy_from_slice(&10u32.to_be_bytes());
        if ResponseParser::new(&ok_resp).is_err() {
            return TestResult::Fail("success extend response rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "tpm/commands",
        smoke_tpm_pcr_extend_response_rejects_truncated_and_error_rc
    );

    fn smoke_tpm_response_parser_rejects_short_buf() -> TestResult {
        use crate::commands::ResponseParser;
        use crate::types::{TpmError, TpmRc};
        // < 10 bytes → BadResponse.
        match ResponseParser::new(&[0u8; 9]) {
            Err(TpmError::BadResponse) => {}
            _ => return TestResult::Fail("short buf didn't surface BadResponse"),
        }
        // Non-zero RC → Rc(TpmRc::Failure) — TPM_RC_FAILURE = 0x101
        // maps to the typed Failure category per TCG Part 2 §6.6.
        let mut buf = [0u8; 10];
        buf[2..6].copy_from_slice(&10u32.to_be_bytes()); // size
        buf[6..10].copy_from_slice(&0x101u32.to_be_bytes()); // RC = TPM_RC_FAILURE
        match ResponseParser::new(&buf) {
            Err(TpmError::Rc(TpmRc::Failure)) => {}
            _ => return TestResult::Fail("TPM_RC_FAILURE didn't map to Rc(Failure)"),
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm/commands", smoke_tpm_response_parser_rejects_short_buf);

    fn smoke_tpm_rc_categorises_common_codes() -> TestResult {
        use crate::types::TpmRc;
        // VER1 codes from TCG Part 2 §6.6, table 16.
        if TpmRc::from_rc(0x100) != TpmRc::Initialize {
            return TestResult::Fail("0x100 ≠ Initialize");
        }
        if TpmRc::from_rc(0x101) != TpmRc::Failure {
            return TestResult::Fail("0x101 ≠ Failure");
        }
        if TpmRc::from_rc(0x120) != TpmRc::Disabled {
            return TestResult::Fail("0x120 ≠ Disabled");
        }
        if TpmRc::from_rc(0x922) != TpmRc::Retry {
            return TestResult::Fail("0x922 ≠ Retry");
        }
        if TpmRc::from_rc(0x921) != TpmRc::Lockout {
            return TestResult::Fail("0x921 ≠ Lockout");
        }
        if TpmRc::from_rc(0x920) != TpmRc::NvRate {
            return TestResult::Fail("0x920 ≠ NvRate");
        }
        if TpmRc::from_rc(0x923) != TpmRc::NvUnavailable {
            return TestResult::Fail("0x923 ≠ NvUnavailable");
        }
        if TpmRc::from_rc(0x01E) != TpmRc::BadTag {
            return TestResult::Fail("0x01E ≠ BadTag");
        }
        // FMT1 codes — base error in bits 0..5, format bit (7) set.
        // TPM_RC_VALUE base = 0x04 ⇒ encoded with parameter index 1
        // as 0x0184 (bit 7 = 0x80, bit 8 = 0x100 selects param 1).
        if TpmRc::from_rc(0x184) != TpmRc::Value {
            return TestResult::Fail("FMT1 0x184 ≠ Value");
        }
        // TPM_RC_HANDLE base = 0x0B ⇒ 0x18B etc.
        if TpmRc::from_rc(0x18B) != TpmRc::Handle {
            return TestResult::Fail("FMT1 0x18B ≠ Handle");
        }
        if TpmRc::from_rc(0x195) != TpmRc::Size {
            return TestResult::Fail("FMT1 0x195 ≠ Size");
        }
        // Unrecognised codes fall through to Other(raw).
        match TpmRc::from_rc(0x7FF) {
            TpmRc::Other(0x7FF) => {}
            _ => return TestResult::Fail("unknown VER1 didn't fall through to Other"),
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm/commands", smoke_tpm_rc_categorises_common_codes);

    fn smoke_tpm_response_parser_get_random_decodes_tail() -> TestResult {
        use crate::commands::ResponseParser;
        // 10-byte header (RC=0) + 2-byte size + 4 random bytes.
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(&0x8001u16.to_be_bytes()); // tag
        buf.extend_from_slice(&16u32.to_be_bytes()); // size
        buf.extend_from_slice(&0u32.to_be_bytes()); // RC
        buf.extend_from_slice(&4u16.to_be_bytes()); // random size
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let p = ResponseParser::new(&buf).expect("parse");
        let r = p.parse_get_random().expect("parse_get_random");
        if r != [0xDE, 0xAD, 0xBE, 0xEF] {
            return TestResult::Fail("random tail decoded wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "tpm/commands",
        smoke_tpm_response_parser_get_random_decodes_tail
    );

    // ── deep tpm/types coverage ───────────────────────────────────────

    fn smoke_tpm_types_pcr_set_contains_walks_full_range() -> TestResult {
        use crate::types::PcrSet;
        // ALL contains every PCR 0..32; out-of-range (>=32) returns false.
        for pcr in 0u32..32 {
            if !PcrSet::ALL.contains(pcr) {
                return TestResult::Fail("ALL didn't contain a PCR in range");
            }
        }
        if PcrSet::ALL.contains(32) {
            return TestResult::Fail("ALL.contains(32) should be false");
        }
        if PcrSet::ALL.contains(u32::MAX) {
            return TestResult::Fail("ALL.contains(u32::MAX) should be false");
        }
        // NONE contains nothing.
        for pcr in 0u32..32 {
            if PcrSet::NONE.contains(pcr) {
                return TestResult::Fail("NONE contained a PCR");
            }
        }
        // Single-bit mask: PcrSet(1 << 5) contains only PCR 5.
        let just5 = PcrSet(1u32 << 5);
        if !just5.contains(5) {
            return TestResult::Fail("just5 didn't contain 5");
        }
        if just5.contains(6) || just5.contains(4) {
            return TestResult::Fail("just5 contained a non-5 PCR");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "tpm/types",
        smoke_tpm_types_pcr_set_contains_walks_full_range
    );

    fn smoke_tpm_error_variants_distinct() -> TestResult {
        use crate::types::{TpmError, TpmRc};
        let all = [
            TpmError::NotPresent,
            TpmError::LocalityTimeout,
            TpmError::BusyTimeout,
            TpmError::NoCommandBuffer,
            TpmError::BadResponse,
            TpmError::InvalidArgs,
            TpmError::Denied,
            TpmError::HardwareError,
            TpmError::Rc(TpmRc::Failure),
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("TpmError variants collapsed");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("tpm/types", smoke_tpm_error_variants_distinct);
}
