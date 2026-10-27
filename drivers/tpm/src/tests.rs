//! Smoke tests for narf-drivers-tpm.
//!
//! Tests are collected by `narf-kernel-test` and run by the xtask
//! smoke harness. No async needed — all tests are synchronous
//! codec / mock-register exercises.

#[cfg(any(test, feature = "kernel-test"))]
mod smokes {
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── CRB register layout ───────────────────────────────────────────

    fn smoke_crb_register_offsets() -> TestResult {
        use crate::crb::*;
        // Spot-check every register offset against the CRB spec §6 table.
        // Linux tpm_crb.c uses struct-field offsets; we verify our
        // constants match the PTP layout.
        if REG_LOC_STATE != 0x000 {
            return TestResult::Fail("REG_LOC_STATE != 0x000");
        }
        if REG_LOC_CTRL != 0x008 {
            return TestResult::Fail("REG_LOC_CTRL != 0x008");
        }
        if REG_LOC_STS != 0x00C {
            return TestResult::Fail("REG_LOC_STS != 0x00C");
        }
        if REG_INTF_ID != 0x030 {
            return TestResult::Fail("REG_INTF_ID != 0x030");
        }
        if REG_CTRL_REQ != 0x040 {
            return TestResult::Fail("REG_CTRL_REQ != 0x040");
        }
        if REG_CTRL_STS != 0x044 {
            return TestResult::Fail("REG_CTRL_STS != 0x044");
        }
        if REG_CTRL_CANCEL != 0x048 {
            return TestResult::Fail("REG_CTRL_CANCEL != 0x048");
        }
        if REG_CTRL_START != 0x04C {
            return TestResult::Fail("REG_CTRL_START != 0x04C");
        }
        if REG_CMD_SIZE != 0x058 {
            return TestResult::Fail("REG_CMD_SIZE != 0x058");
        }
        if REG_CMD_LADDR != 0x05C {
            return TestResult::Fail("REG_CMD_LADDR != 0x05C");
        }
        if REG_CMD_HADDR != 0x060 {
            return TestResult::Fail("REG_CMD_HADDR != 0x060");
        }
        if REG_RSP_SIZE != 0x068 {
            return TestResult::Fail("REG_RSP_SIZE != 0x068");
        }
        if REG_RSP_LADDR != 0x06C {
            return TestResult::Fail("REG_RSP_LADDR != 0x06C");
        }
        if REG_RSP_HADDR != 0x070 {
            return TestResult::Fail("REG_RSP_HADDR != 0x070");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/crb", smoke_crb_register_offsets);

    // ── CRB locality request/grant sequence ───────────────────────────

    fn smoke_crb_locality_grant_sequence() -> TestResult {
        use crate::crb::{
            acquire_locality, MockCrb, LOC_CTRL_REQUEST, LOC_STATE_LOC_ASSIGNED, REG_LOC_CTRL,
            REG_LOC_STATE,
        };
        let mut m = MockCrb::new();
        // Simulate TPM asserting locAssigned on the first read
        // after the host writes LOC_CTRL.Request.
        m.install_hook(REG_LOC_STATE, |regs| {
            regs[REG_LOC_STATE / 4] |= LOC_STATE_LOC_ASSIGNED;
        });
        if acquire_locality(&mut m).is_err() {
            return TestResult::Fail("acquire_locality failed on happy path");
        }
        // The first write must be LOC_CTRL = Request.
        if m.writes.first().copied() != Some((REG_LOC_CTRL, LOC_CTRL_REQUEST)) {
            return TestResult::Fail("first write must be LOC_CTRL.Request");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/crb", smoke_crb_locality_grant_sequence);

    fn smoke_crb_locality_times_out() -> TestResult {
        use crate::crb::{acquire_locality, CrbError, MockCrb};
        // No hook → LOC_STATE stays 0 forever → must time out.
        let mut m = MockCrb::new();
        match acquire_locality(&mut m) {
            Err(CrbError::LocalityTimeout) => TestResult::Pass,
            _ => TestResult::Fail("should time out when locAssigned never asserts"),
        }
    }
    kernel_test_in!("drivers/tpm/crb", smoke_crb_locality_times_out);

    fn smoke_crb_run_command_go_self_clears() -> TestResult {
        use crate::crb::{run_command, MockCrb, CTRL_STS_IDLE, REG_CTRL_START, REG_CTRL_STS};
        let mut m = MockCrb::new();
        m.regs[REG_CTRL_STS / 4] = CTRL_STS_IDLE;
        m.install_hook(REG_CTRL_START, |regs| {
            regs[REG_CTRL_START / 4] = 0; // Go bit self-clears
        });
        let sts = match run_command(&mut m) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("run_command errored on happy path"),
        };
        if sts & CTRL_STS_IDLE == 0 {
            return TestResult::Fail("CTRL_STS.IDLE must be set after command completes");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/crb", smoke_crb_run_command_go_self_clears);

    fn smoke_crb_error_bit_surfaces_failed() -> TestResult {
        use crate::crb::{
            run_command, CrbError, MockCrb, CTRL_STS_ERROR, REG_CTRL_START, REG_CTRL_STS,
        };
        let mut m = MockCrb::new();
        m.regs[REG_CTRL_STS / 4] = CTRL_STS_ERROR;
        m.install_hook(REG_CTRL_START, |regs| {
            regs[REG_CTRL_START / 4] = 0;
        });
        match run_command(&mut m) {
            Err(CrbError::Failed(s)) if s & CTRL_STS_ERROR != 0 => TestResult::Pass,
            _ => TestResult::Fail("CTRL_STS.error must surface as CrbError::Failed"),
        }
    }
    kernel_test_in!("drivers/tpm/crb", smoke_crb_error_bit_surfaces_failed);

    // ── TIS register layout ───────────────────────────────────────────

    fn smoke_tis_register_offsets() -> TestResult {
        use crate::tis::*;
        // Locality-0 offsets must match Linux tpm_tis_core.h macros.
        if tpm_access(0) != 0x0000 {
            return TestResult::Fail("tpm_access(0) != 0x0000");
        }
        if tpm_int_enable(0) != 0x0008 {
            return TestResult::Fail("tpm_int_enable(0) != 0x0008");
        }
        if tpm_int_vector(0) != 0x000C {
            return TestResult::Fail("tpm_int_vector(0) != 0x000C");
        }
        if tpm_int_status(0) != 0x0010 {
            return TestResult::Fail("tpm_int_status(0) != 0x0010");
        }
        if tpm_intf_caps(0) != 0x0014 {
            return TestResult::Fail("tpm_intf_caps(0) != 0x0014");
        }
        if tpm_sts(0) != 0x0018 {
            return TestResult::Fail("tpm_sts(0) != 0x0018");
        }
        if tpm_data_fifo(0) != 0x0024 {
            return TestResult::Fail("tpm_data_fifo(0) != 0x0024");
        }
        if tpm_did_vid(0) != 0x0F00 {
            return TestResult::Fail("tpm_did_vid(0) != 0x0F00");
        }
        // Locality-1 must be shifted by 0x1000.
        if tpm_access(1) != 0x1000 {
            return TestResult::Fail("tpm_access(1) != 0x1000");
        }
        if tpm_sts(1) != 0x1018 {
            return TestResult::Fail("tpm_sts(1) != 0x1018");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tis", smoke_tis_register_offsets);

    fn smoke_tis_locality_request_sequence() -> TestResult {
        use crate::tis::{
            request_locality, MockTis, ACCESS_ACTIVE_LOCALITY, ACCESS_REQUEST_USE, ACCESS_VALID,
        };
        let mut m = MockTis::new();
        // Pre-program the access register so the mock immediately
        // reflects activeLocality + valid when read.
        let acc_off = crate::tis::tpm_access(0);
        m.mem[acc_off] = ACCESS_ACTIVE_LOCALITY | ACCESS_VALID;
        if request_locality(&mut m, 0).is_err() {
            return TestResult::Fail("request_locality failed on happy path");
        }
        // First write must be ACCESS_REQUEST_USE.
        if m.writes.first().map(|w| w.1 as u8) != Some(ACCESS_REQUEST_USE) {
            return TestResult::Fail("first write must be ACCESS.requestUse");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tis", smoke_tis_locality_request_sequence);

    fn smoke_tis_locality_times_out() -> TestResult {
        use crate::tis::{request_locality, MockTis, TisError};
        let mut m = MockTis::new(); // access register = 0 → never grants
        match request_locality(&mut m, 0) {
            Err(TisError::LocalityTimeout) => TestResult::Pass,
            _ => TestResult::Fail("should time out when activeLocality never asserts"),
        }
    }
    kernel_test_in!("drivers/tpm/tis", smoke_tis_locality_times_out);

    // ── TPM2 command header encode ────────────────────────────────────

    fn smoke_tpm2_header_encode() -> TestResult {
        use crate::tpm2::{Header, TPM_CC_STARTUP, TPM_ST_NO_SESSIONS};
        let h = Header {
            tag: TPM_ST_NO_SESSIONS,
            size: 12,
            code: TPM_CC_STARTUP,
        };
        let b = h.encode();
        if b[0..2] != 0x8001u16.to_be_bytes() {
            return TestResult::Fail("tag big-endian encoding failed");
        }
        if b[2..6] != 12u32.to_be_bytes() {
            return TestResult::Fail("size big-endian encoding failed");
        }
        if b[6..10] != TPM_CC_STARTUP.to_be_bytes() {
            return TestResult::Fail("code big-endian encoding failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_header_encode);

    // ── TPM2 response header decode ───────────────────────────────────

    fn smoke_tpm2_header_decode() -> TestResult {
        use crate::tpm2::{Header, TPM_CC_STARTUP, TPM_ST_NO_SESSIONS};
        let h = Header {
            tag: TPM_ST_NO_SESSIONS,
            size: 10,
            code: TPM_CC_STARTUP,
        };
        let buf = h.encode();
        let back = Header::decode(&buf).expect("decode should succeed");
        if back != h {
            return TestResult::Fail("header round-trip failed");
        }
        // Short buffer must fail.
        if Header::decode(&[0u8; 9]).is_ok() {
            return TestResult::Fail("short buffer should fail");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_header_decode);

    fn smoke_tpm2_header_rejects_bad_tag() -> TestResult {
        use crate::tpm2::{CodecError, Header};
        let mut buf = [0u8; 10];
        buf[0..2].copy_from_slice(&0xDEADu16.to_be_bytes());
        match Header::decode(&buf) {
            Err(CodecError::BadTag(0xDEAD)) => TestResult::Pass,
            _ => TestResult::Fail("non-TPM_ST tag must be rejected with BadTag"),
        }
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_header_rejects_bad_tag);

    // ── TPM2_Startup(CLEAR) encode ────────────────────────────────────

    fn smoke_tpm2_startup_clear_encode() -> TestResult {
        use crate::tpm2::commands::startup_clear;
        use crate::tpm2::{TPM_CC_STARTUP, TPM_ST_NO_SESSIONS, TPM_SU_CLEAR};
        let cmd = startup_clear();
        if cmd.len() != 12 {
            return TestResult::Fail("Startup(CLEAR) = 10 hdr + 2 SU = 12 bytes");
        }
        if u16::from_be_bytes([cmd[0], cmd[1]]) != TPM_ST_NO_SESSIONS {
            return TestResult::Fail("tag != NO_SESSIONS");
        }
        if u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) != 12 {
            return TestResult::Fail("size field != 12");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_STARTUP {
            return TestResult::Fail("command code != Startup");
        }
        if u16::from_be_bytes([cmd[10], cmd[11]]) != TPM_SU_CLEAR {
            return TestResult::Fail("TPM_SU operand != CLEAR");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_startup_clear_encode);

    // ── TPM2_GetCapability encode + decode ────────────────────────────

    fn smoke_tpm2_get_capability_encode() -> TestResult {
        use crate::tpm2::commands::get_capability;
        use crate::tpm2::{TPM_CAP_PCRS, TPM_CC_GET_CAPABILITY, TPM_ST_NO_SESSIONS};
        let cmd = get_capability(TPM_CAP_PCRS, 0, 8);
        // 10 hdr + 4 cap + 4 prop + 4 count = 22 bytes.
        if cmd.len() != 22 {
            return TestResult::Fail("GetCapability = 22 bytes");
        }
        if u16::from_be_bytes([cmd[0], cmd[1]]) != TPM_ST_NO_SESSIONS {
            return TestResult::Fail("tag mismatch");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_GET_CAPABILITY {
            return TestResult::Fail("opcode mismatch");
        }
        if u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) != TPM_CAP_PCRS {
            return TestResult::Fail("capability field wrong");
        }
        if u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]) != 8 {
            return TestResult::Fail("count field wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_get_capability_encode);

    // ── #941: Create template + new builders + structured parsers ─────

    fn smoke_tpm2_create_template_uses_objects_encoder() -> TestResult {
        use crate::tpm2::commands::create_rsa2048_under_owner;
        use crate::tpm2::objects::{
            rsa2048_template, OBJ_DECRYPT, OBJ_FIXED_PARENT, OBJ_FIXED_TPM,
            OBJ_SENSITIVE_DATA_ORIGIN, OBJ_ST_CLEAR, OBJ_USER_WITH_AUTH,
        };
        let cmd = create_rsa2048_under_owner(&[]);
        let template = rsa2048_template(
            OBJ_FIXED_TPM
                | OBJ_ST_CLEAR
                | OBJ_FIXED_PARENT
                | OBJ_SENSITIVE_DATA_ORIGIN
                | OBJ_USER_WITH_AUTH
                | OBJ_DECRYPT,
        );
        // The frame must carry the objects.rs template verbatim…
        if !cmd
            .windows(template.len())
            .any(|w| w == template.as_slice())
        {
            return TestResult::Fail("Create inPublic != objects::rsa2048_template");
        }
        // …and none of the pre-#941 malformed encoding: the old
        // inline template wrote the symmetric field as
        // TPM_ALG_SHA256 (0x000B) followed by a stray 0x0080
        // "keyBits" word and exponent 1.
        let malformed: [u8; 6] = [0x00, 0x0B, 0x00, 0x80, 0x00, 0x10];
        if cmd.windows(malformed.len()).any(|w| w == malformed) {
            return TestResult::Fail("Create still carries the malformed template bytes");
        }
        let bad_exponent: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
        // The template's exponent field is 0 (→ 65537); the only
        // 00 00 00 01 in a correct frame is the TPM_CC / count
        // fields — check the template region itself instead: the
        // four bytes before the unique-size field.
        let t = &template;
        if t[t.len() - 6..t.len() - 2] == bad_exponent {
            return TestResult::Fail("template exponent must be 0, not 1");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/tpm/tpm2",
        smoke_tpm2_create_template_uses_objects_encoder
    );

    fn smoke_tpm2_hierarchy_session_builders_encode() -> TestResult {
        use crate::tpm2::commands as cmds;
        use crate::tpm2::*;
        let cc = |cmd: &[u8]| u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
        let tag = |cmd: &[u8]| u16::from_be_bytes([cmd[0], cmd[1]]);
        let size_ok =
            |cmd: &[u8]| u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) as usize == cmd.len();

        // Clear: SESSIONS, platform handle, PW area only.
        let cmd = cmds::clear();
        if tag(&cmd) != TPM_ST_SESSIONS || cc(&cmd) != TPM_CC_CLEAR || !size_ok(&cmd) {
            return TestResult::Fail("Clear header wrong");
        }
        if cmd.len() != 23
            || u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) != TPM_RH_PLATFORM
        {
            return TestResult::Fail("Clear frame shape wrong");
        }
        // ClearControl(true): one trailing TPMI_YES_NO byte.
        let cmd = cmds::clear_control(true);
        if cc(&cmd) != TPM_CC_CLEAR_CONTROL || cmd.len() != 24 || cmd[23] != 1 {
            return TestResult::Fail("ClearControl frame wrong");
        }
        // FlushContext: NO_SESSIONS + handle, 14 bytes.
        let cmd = cmds::flush_context(0x8000_0001);
        if tag(&cmd) != TPM_ST_NO_SESSIONS
            || cc(&cmd) != TPM_CC_FLUSH_CONTEXT
            || cmd.len() != 14
            || u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) != 0x8000_0001
        {
            return TestResult::Fail("FlushContext frame wrong");
        }
        // EvictControl: two handles, PW area, persistent handle.
        let cmd = cmds::evict_control(TPM_RH_OWNER, 0x8000_0100, 0x8100_0000);
        if cc(&cmd) != TPM_CC_EVICT_CONTROL || cmd.len() != 35 {
            return TestResult::Fail("EvictControl frame wrong");
        }
        if u32::from_be_bytes([cmd[31], cmd[32], cmd[33], cmd[34]]) != 0x8100_0000 {
            return TestResult::Fail("EvictControl persistent handle misplaced");
        }
        // StartAuthSession: NO_SESSIONS, two handles, TPM_SE_POLICY,
        // NULL symmetric, SHA-256 authHash.
        let cmd = cmds::start_auth_session(
            TPM_RH_NULL,
            TPM_RH_NULL,
            &[],
            &[],
            TPM_SE_POLICY,
            TPM_ALG_SHA256,
        );
        if cc(&cmd) != TPM_CC_START_AUTH_SESSION || cmd.len() != 27 || !size_ok(&cmd) {
            return TestResult::Fail("StartAuthSession frame wrong");
        }
        if cmd[22] != TPM_SE_POLICY
            || u16::from_be_bytes([cmd[23], cmd[24]]) != TPM_ALG_NULL
            || u16::from_be_bytes([cmd[25], cmd[26]]) != TPM_ALG_SHA256
        {
            return TestResult::Fail("StartAuthSession parameters wrong");
        }
        // PolicyPCR: SESSIONS; the auth area is the session itself
        // with continueSession (0x01) at offset 24.
        let mut mask = [0u8; 3];
        mask[0] = 1 << 7;
        let cmd = cmds::policy_pcr(0x0200_0001, &[], &[(TPM_ALG_SHA256, &mask)]);
        if tag(&cmd) != TPM_ST_SESSIONS || cc(&cmd) != TPM_CC_POLICY_PCR || !size_ok(&cmd) {
            return TestResult::Fail("PolicyPCR header wrong");
        }
        if u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) != 0x0200_0001
            || u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]) != 0x0200_0001
            || cmd[24] != 0x01
        {
            return TestResult::Fail("PolicyPCR auth area != the session with continueSession");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/tpm/tpm2",
        smoke_tpm2_hierarchy_session_builders_encode
    );

    fn smoke_tpm2_structured_response_parsers() -> TestResult {
        use crate::tpm2::commands as cmds;
        // Frame helper: SESSIONS success response with the given
        // handle area + parameter bytes + a 5-byte auth area.
        fn sessions_frame(handle: Option<u32>, params: &[u8]) -> alloc::vec::Vec<u8> {
            let mut r = alloc::vec::Vec::new();
            r.extend_from_slice(&0x8002u16.to_be_bytes());
            r.extend_from_slice(&0u32.to_be_bytes()); // size, patched below
            r.extend_from_slice(&0u32.to_be_bytes()); // rc = SUCCESS
            if let Some(h) = handle {
                r.extend_from_slice(&h.to_be_bytes());
            }
            r.extend_from_slice(&(params.len() as u32).to_be_bytes());
            r.extend_from_slice(params);
            r.extend_from_slice(&[0u8; 5]); // auth area
            let n = r.len() as u32;
            r[2..6].copy_from_slice(&n.to_be_bytes());
            r
        }
        fn tpm2b(data: &[u8]) -> alloc::vec::Vec<u8> {
            let mut v = alloc::vec::Vec::new();
            v.extend_from_slice(&(data.len() as u16).to_be_bytes());
            v.extend_from_slice(data);
            v
        }

        // Create: outPrivate/outPublic/creationData/creationHash +
        // ticket(tag, hierarchy, digest).
        let mut params = alloc::vec::Vec::new();
        params.extend_from_slice(&tpm2b(&[0xAA; 4]));
        params.extend_from_slice(&tpm2b(&[0xBB; 6]));
        params.extend_from_slice(&tpm2b(&[]));
        params.extend_from_slice(&tpm2b(&[0xCC; 4]));
        params.extend_from_slice(&0x8021u16.to_be_bytes());
        params.extend_from_slice(&0x4000_0001u32.to_be_bytes());
        params.extend_from_slice(&tpm2b(&[0xDD; 2]));
        let frame = sessions_frame(None, &params);
        match cmds::parse_create_response(&frame) {
            Ok(o)
                if o.out_private == alloc::vec![0xAA; 4]
                    && o.out_public == alloc::vec![0xBB; 6]
                    && o.creation_hash == alloc::vec![0xCC; 4]
                    && o.ticket_tag == 0x8021
                    && o.ticket_hierarchy == 0x4000_0001
                    && o.ticket_digest == alloc::vec![0xDD; 2] => {}
            _ => return TestResult::Fail("Create response parsed incorrectly"),
        }
        // CreatePrimary: same params behind a handle.
        let frame = sessions_frame(Some(0x8000_0100), &params);
        match cmds::parse_create_primary_response(&frame) {
            Ok((0x8000_0100, o)) if o.out_public == alloc::vec![0xBB; 6] => {}
            _ => return TestResult::Fail("CreatePrimary response parsed incorrectly"),
        }
        // Load: handle + name TPM2B.
        let frame = sessions_frame(Some(0x8000_0200), &tpm2b(&[1, 2, 3]));
        match cmds::parse_load_response(&frame) {
            Ok((0x8000_0200, name)) if name == alloc::vec![1, 2, 3] => {}
            _ => return TestResult::Fail("Load response parsed incorrectly"),
        }
        // Unseal / NV_Read: a single TPM2B parameter.
        let frame = sessions_frame(None, &tpm2b(b"secret"));
        match cmds::parse_unseal_response(&frame) {
            Ok(v) if v == b"secret" => {}
            _ => return TestResult::Fail("Unseal response parsed incorrectly"),
        }
        match cmds::parse_nv_read_response(&frame) {
            Ok(v) if v == b"secret" => {}
            _ => return TestResult::Fail("NV_Read response parsed incorrectly"),
        }
        // GetTestResult: NO_SESSIONS, TPM2B + u32.
        let mut r = alloc::vec::Vec::new();
        r.extend_from_slice(&0x8001u16.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&tpm2b(&[9, 9]));
        r.extend_from_slice(&0x0000_0000u32.to_be_bytes());
        let n = r.len() as u32;
        r[2..6].copy_from_slice(&n.to_be_bytes());
        match cmds::parse_get_test_result_response(&r) {
            Ok((data, 0)) if data == alloc::vec![9, 9] => {}
            _ => return TestResult::Fail("GetTestResult response parsed incorrectly"),
        }
        // StartAuthSession: handle + nonce TPM2B, NO_SESSIONS.
        let mut r = alloc::vec::Vec::new();
        r.extend_from_slice(&0x8001u16.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&0x0200_0001u32.to_be_bytes());
        r.extend_from_slice(&tpm2b(&[7; 16]));
        let n = r.len() as u32;
        r[2..6].copy_from_slice(&n.to_be_bytes());
        match cmds::parse_start_auth_session_response(&r) {
            Ok((0x0200_0001, nonce)) if nonce == alloc::vec![7; 16] => {}
            _ => return TestResult::Fail("StartAuthSession response parsed incorrectly"),
        }
        // GetCapability envelope + property data.
        let mut r = alloc::vec::Vec::new();
        r.extend_from_slice(&0x8001u16.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.push(0u8); // moreData = NO
        r.extend_from_slice(&6u32.to_be_bytes()); // TPM_CAP_TPM_PROPERTIES
        r.extend_from_slice(&1u32.to_be_bytes()); // count
        r.extend_from_slice(&0x105u32.to_be_bytes()); // PT_MANUFACTURER
        r.extend_from_slice(&0x4E41_5246u32.to_be_bytes()); // "NARF"
        let n = r.len() as u32;
        r[2..6].copy_from_slice(&n.to_be_bytes());
        match cmds::parse_get_capability_response(&r) {
            Ok(p) if !p.more_data && p.capability == 6 => {
                match cmds::parse_tagged_properties(&p.data) {
                    Ok(entries) if entries == alloc::vec![(0x105, 0x4E41_5246)] => {}
                    _ => return TestResult::Fail("tagged properties parsed incorrectly"),
                }
            }
            _ => return TestResult::Fail("GetCapability response parsed incorrectly"),
        }
        // Negatives: truncated parameters, parameterSize overrun,
        // and a non-zero RC must all be errors, never panics.
        let frame = sessions_frame(None, &params[..4]);
        if cmds::parse_create_response(&frame).is_ok() {
            return TestResult::Fail("truncated Create response accepted");
        }
        let mut frame = sessions_frame(None, &params);
        let bogus = (params.len() + 64) as u32;
        frame[10..14].copy_from_slice(&bogus.to_be_bytes());
        if cmds::parse_create_response(&frame).is_ok() {
            return TestResult::Fail("parameterSize overrun accepted");
        }
        let mut frame = sessions_frame(None, &params);
        frame[9] = 0x43; // rc low byte → TPM_RC_COMMAND_CODE-ish
        if cmds::parse_create_response(&frame).is_ok() {
            return TestResult::Fail("non-zero RC accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_structured_response_parsers);

    // ── TPM2_GetRandom encode + decode 32-byte response ───────────────

    fn smoke_tpm2_get_random_encode() -> TestResult {
        use crate::tpm2::commands::get_random;
        use crate::tpm2::TPM_CC_GET_RANDOM;
        let cmd = get_random(32);
        if cmd.len() != 12 {
            return TestResult::Fail("GetRandom = 10 hdr + 2 length = 12 bytes");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_GET_RANDOM {
            return TestResult::Fail("opcode mismatch");
        }
        if u16::from_be_bytes([cmd[10], cmd[11]]) != 32 {
            return TestResult::Fail("bytesRequested should round-trip to 32");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_get_random_encode);

    fn smoke_tpm2_get_random_response_decode() -> TestResult {
        use crate::tpm2::commands::parse_get_random_response;
        // Simulate a 4-byte random response body from the TPM.
        let body: [u8; 6] = [0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let r = parse_get_random_response(&body).expect("parse should succeed");
        if r != [0xDE, 0xAD, 0xBE, 0xEF] {
            return TestResult::Fail("decoded bytes mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_get_random_response_decode);

    // ── TPM2_PCR_Read encode (SHA-256, PCRs 0..23) ────────────────────

    fn smoke_tpm2_pcr_read_all_sha256() -> TestResult {
        use crate::tpm2::commands::pcr_read;
        use crate::tpm2::{TPM_ALG_SHA256, TPM_CC_PCR_READ, TPM_ST_NO_SESSIONS};
        // All 24 PCRs selected: 3 bytes all-ones.
        let cmd = pcr_read(TPM_ALG_SHA256, &[0xFF, 0xFF, 0xFF]);
        if u16::from_be_bytes([cmd[0], cmd[1]]) != TPM_ST_NO_SESSIONS {
            return TestResult::Fail("tag mismatch");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_PCR_READ {
            return TestResult::Fail("opcode mismatch");
        }
        // selectionCount = 1
        if u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) != 1 {
            return TestResult::Fail("selectionCount != 1");
        }
        // hashAlg = SHA256
        if u16::from_be_bytes([cmd[14], cmd[15]]) != TPM_ALG_SHA256 {
            return TestResult::Fail("hashAlg != SHA256");
        }
        // sizeofSelect = 3
        if cmd[16] != 3 {
            return TestResult::Fail("sizeofSelect != 3");
        }
        // bitmap = all-ones
        if cmd[17..20] != [0xFF, 0xFF, 0xFF] {
            return TestResult::Fail("PCR bitmap should be all-ones for full bank");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_pcr_read_all_sha256);

    // ── TPM2_PCR_Extend encode ────────────────────────────────────────

    fn smoke_tpm2_pcr_extend_sha256_pcr4() -> TestResult {
        use crate::tpm2::commands::pcr_extend_sha256;
        use crate::tpm2::{TPM_ALG_SHA256, TPM_CC_PCR_EXTEND, TPM_RS_PW, TPM_ST_SESSIONS};
        let digest = [0xA5u8; 32];
        let cmd = pcr_extend_sha256(4, &digest);
        // TPM_ST_SESSIONS because we include an auth session.
        if u16::from_be_bytes([cmd[0], cmd[1]]) != TPM_ST_SESSIONS {
            return TestResult::Fail("tag should be TPM_ST_SESSIONS for PCR_Extend");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_PCR_EXTEND {
            return TestResult::Fail("opcode mismatch");
        }
        // pcrHandle = 4 at bytes 10..13
        if u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) != 4 {
            return TestResult::Fail("pcrHandle != 4");
        }
        // authorizationSize = 9 at bytes 14..17
        if u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]) != 9 {
            return TestResult::Fail("authorizationSize != 9");
        }
        // sessionHandle = TPM_RS_PW at bytes 18..21
        if u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]) != TPM_RS_PW {
            return TestResult::Fail("session handle != TPM_RS_PW");
        }
        // hashAlg = SHA256 at bytes 31..32
        // body start=10; pcrHandle(4)+authSize(4)+auth(9)+count(4) = 21 → 10+21=31
        if u16::from_be_bytes([cmd[31], cmd[32]]) != TPM_ALG_SHA256 {
            return TestResult::Fail("hashAlg != SHA256");
        }
        // digest = 32 × 0xA5 at bytes 33..65
        if cmd[33..65] != digest {
            return TestResult::Fail("digest bytes mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/tpm2", smoke_tpm2_pcr_extend_sha256_pcr4);

    // ── ACPI probe — MSFT0101 HID match ──────────────────────────────

    fn smoke_acpi_probe_msft0101_match() -> TestResult {
        use crate::probe::matches_tpm2_hid;
        if !matches_tpm2_hid("MSFT0101") {
            return TestResult::Fail("MSFT0101 must match");
        }
        if !matches_tpm2_hid("PNP0C31") {
            return TestResult::Fail("PNP0C31 (compat ID) must match");
        }
        if matches_tpm2_hid("ACPI0007") {
            return TestResult::Fail("ACPI0007 must not match");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/probe", smoke_acpi_probe_msft0101_match);

    // ── TPM2 start-method classification ──────────────────────────────
    //
    // TPM2 *table parsing* is owned by `narf_acpi` (composition,
    // #934): this crate's duplicate parser (`parse_tpm2_table`) and
    // its smoke were deleted. What remains here is the start-method
    // vocabulary used to classify a decoded table.

    fn smoke_tpm2_start_method_is_crb() -> TestResult {
        use crate::probe::{
            start_method_is_crb, ACPI_TPM2_COMMAND_BUFFER, ACPI_TPM2_COMMAND_BUFFER_WITH_ARM_SMC,
            ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD, ACPI_TPM2_CRB_WITH_ARM_FFA,
            ACPI_TPM2_MEMORY_MAPPED, ACPI_TPM2_NOT_ALLOWED,
        };
        for m in [
            ACPI_TPM2_COMMAND_BUFFER,
            ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD,
            ACPI_TPM2_MEMORY_MAPPED,
        ] {
            if !start_method_is_crb(m) {
                return TestResult::Fail("CRB start method not recognised as CRB");
            }
        }
        for m in [
            ACPI_TPM2_NOT_ALLOWED,
            ACPI_TPM2_COMMAND_BUFFER_WITH_ARM_SMC,
            ACPI_TPM2_CRB_WITH_ARM_FFA,
        ] {
            if start_method_is_crb(m) {
                return TestResult::Fail("non-MMIO start method misclassified as CRB");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/probe", smoke_tpm2_start_method_is_crb);

    // ── PCR selection bitmap encoding ────────────────────────────────

    fn smoke_pcr_selection_encode() -> TestResult {
        use crate::tpm2::pcr::{HashBank, PcrSelection};
        // PCR 0 = byte 0 bit 0.
        let s = PcrSelection::single(HashBank::Sha256, 0);
        let enc = s.encode();
        if enc[0..2] != 0x000Bu16.to_be_bytes() {
            return TestResult::Fail("hashAlg should be SHA256 (0x000B)");
        }
        if enc[2] != 3 {
            return TestResult::Fail("sizeofSelect should be 3");
        }
        if enc[3] != 0x01 || enc[4] != 0 || enc[5] != 0 {
            return TestResult::Fail("PCR 0 bitmap: byte[0] bit 0");
        }
        // PCR 23 = byte 2 bit 7.
        let s23 = PcrSelection::single(HashBank::Sha256, 23);
        let enc23 = s23.encode();
        if enc23[3] != 0 || enc23[4] != 0 || enc23[5] != 0x80 {
            return TestResult::Fail("PCR 23 bitmap: byte[2] bit 7");
        }
        // All-PCRs selection must have all bits set.
        let all = PcrSelection::all(HashBank::Sha256);
        let enc_all = all.encode();
        if enc_all[3..6] != [0xFF, 0xFF, 0xFF] {
            return TestResult::Fail("all-PCRs bitmap should be 0xFF,0xFF,0xFF");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/pcr", smoke_pcr_selection_encode);

    fn smoke_pcr_selection_contains() -> TestResult {
        use crate::tpm2::pcr::{HashBank, PcrSelection};
        let sel = PcrSelection::single(HashBank::Sha256, 7);
        if !sel.contains(7) {
            return TestResult::Fail("selection must contain PCR 7");
        }
        if sel.contains(6) || sel.contains(8) {
            return TestResult::Fail("selection must not contain other PCRs");
        }
        if sel.contains(24) {
            return TestResult::Fail("PCR >= 24 must not be contained");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/pcr", smoke_pcr_selection_contains);

    // ── NV index commands ─────────────────────────────────────────────

    fn smoke_nv_define_space_cmd_structure() -> TestResult {
        use crate::tpm2::commands::nv_define_space;
        use crate::tpm2::{TPM_CC_NV_DEFINE_SPACE, TPM_ST_SESSIONS};
        let cmd = nv_define_space(0x0150_0000, 32, 0x4002);
        if u16::from_be_bytes([cmd[0], cmd[1]]) != TPM_ST_SESSIONS {
            return TestResult::Fail("NV_DefineSpace should use TPM_ST_SESSIONS");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_NV_DEFINE_SPACE {
            return TestResult::Fail("opcode mismatch");
        }
        // authHandle = TPM_RH_OWNER at bytes 10..13
        if u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) != crate::tpm2::TPM_RH_OWNER {
            return TestResult::Fail("authHandle != TPM_RH_OWNER");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/nv", smoke_nv_define_space_cmd_structure);

    fn smoke_nv_read_cmd_structure() -> TestResult {
        use crate::tpm2::commands::nv_read;
        use crate::tpm2::{TPM_CC_NV_READ, TPM_ST_SESSIONS};
        let cmd = nv_read(0x0150_0001, 32, 0);
        if u16::from_be_bytes([cmd[0], cmd[1]]) != TPM_ST_SESSIONS {
            return TestResult::Fail("NV_Read should use TPM_ST_SESSIONS");
        }
        if u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) != TPM_CC_NV_READ {
            return TestResult::Fail("opcode mismatch for NV_Read");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/nv", smoke_nv_read_cmd_structure);

    // ── Key type algorithm IDs ────────────────────────────────────────

    fn smoke_key_type_alg_ids() -> TestResult {
        use crate::tpm2::objects::KeyType;
        use crate::tpm2::{TPM_ALG_ECC, TPM_ALG_RSA, TPM_ECC_NIST_P256, TPM_ECC_NIST_P384};
        if KeyType::Rsa2048.tpm_alg() != TPM_ALG_RSA {
            return TestResult::Fail("Rsa2048 alg != TPM_ALG_RSA");
        }
        if KeyType::EccP256.tpm_alg() != TPM_ALG_ECC {
            return TestResult::Fail("EccP256 alg != TPM_ALG_ECC");
        }
        if KeyType::EccP384.tpm_alg() != TPM_ALG_ECC {
            return TestResult::Fail("EccP384 alg != TPM_ALG_ECC");
        }
        if KeyType::EccP256.ecc_curve() != TPM_ECC_NIST_P256 {
            return TestResult::Fail("EccP256 curve != NIST_P256");
        }
        if KeyType::EccP384.ecc_curve() != TPM_ECC_NIST_P384 {
            return TestResult::Fail("EccP384 curve != NIST_P384");
        }
        if KeyType::Rsa2048.ecc_curve() != 0 {
            return TestResult::Fail("RSA key must return 0 for ecc_curve");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/objects", smoke_key_type_alg_ids);

    // ── Tpm2bPublic encode / field accessors ─────────────────────────

    fn smoke_tpm2b_public_encode() -> TestResult {
        use crate::tpm2::objects::{rsa2048_template, Tpm2bPublic, OBJ_ATTR_SEAL};
        let inner = rsa2048_template(OBJ_ATTR_SEAL);
        let pub_obj = Tpm2bPublic::from_bytes(&inner);
        let encoded = pub_obj.encode();
        // First 2 bytes = size of inner as BE u16.
        let size = u16::from_be_bytes([encoded[0], encoded[1]]) as usize;
        if size != inner.len() {
            return TestResult::Fail("TPM2B_PUBLIC size prefix mismatch");
        }
        if &encoded[2..] != inner.as_slice() {
            return TestResult::Fail("TPM2B_PUBLIC body mismatch after size prefix");
        }
        // algorithm() should return TPM_ALG_RSA (0x0001)
        if pub_obj.algorithm() != Some(crate::tpm2::TPM_ALG_RSA) {
            return TestResult::Fail("algorithm() should return TPM_ALG_RSA");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/objects", smoke_tpm2b_public_encode);

    // ── CRB program_buffers writes all 6 registers ───────────────────

    fn smoke_crb_program_buffers_six_writes() -> TestResult {
        use crate::crb::{
            program_buffers, MockCrb, REG_CMD_HADDR, REG_CMD_LADDR, REG_CMD_SIZE, REG_RSP_HADDR,
            REG_RSP_LADDR, REG_RSP_SIZE,
        };
        let mut m = MockCrb::new();
        let cmd_phys: u64 = 0x0000_0001_DEAD_0000;
        let rsp_phys: u64 = 0x0000_0002_BEEF_0000;
        program_buffers(&mut m, cmd_phys, 128, rsp_phys, 512);
        let want = [
            (REG_CMD_SIZE, 128u32),
            (REG_CMD_LADDR, cmd_phys as u32),
            (REG_CMD_HADDR, (cmd_phys >> 32) as u32),
            (REG_RSP_SIZE, 512u32),
            (REG_RSP_LADDR, rsp_phys as u32),
            (REG_RSP_HADDR, (rsp_phys >> 32) as u32),
        ];
        for (reg, val) in want {
            if !m.writes.iter().any(|w| w.0 == reg && w.1 == val) {
                return TestResult::Fail("missing expected buffer-program write");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/crb", smoke_crb_program_buffers_six_writes);

    // ── devfs_bridge smoke tests ──────────────────────────────────────

    // Minimal sync future poller for no_std tests.
    fn poll_once_sync<F: core::future::Future>(fut: F) -> Option<F::Output> {
        use core::task::{Context, RawWaker, RawWakerVTable, Waker};
        unsafe fn no_clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTAB)
        }
        unsafe fn no_op(_: *const ()) {}
        static VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        let raw = RawWaker::new(core::ptr::null(), &VTAB);
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let waker = unsafe { Waker::from_raw(raw) };
        let mut cx = Context::from_waker(&waker);
        let mut pinned = core::pin::pin!(fut);
        match pinned.as_mut().poll(&mut cx) {
            core::task::Poll::Ready(v) => Some(v),
            core::task::Poll::Pending => None,
        }
    }

    /// A mock transport that returns a fixed canned GetRandom response
    /// containing 8 known bytes: [0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04].
    ///
    /// Response layout (TPM2_GetRandom Part 3 §18.2):
    ///   header (10 bytes) + TPM2B_DIGEST size(u16) + 8 random bytes
    struct GetRandomMock;
    impl crate::devfs_bridge::TpmTransport for GetRandomMock {
        fn submit(&self, _cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, ()> {
            let mut r = alloc::vec![0u8; 10 + 2 + 8];
            // tag = TPM_ST_NO_SESSIONS
            r[0] = 0x80;
            r[1] = 0x01;
            // size = 20
            let sz = 20u32;
            r[2] = (sz >> 24) as u8;
            r[3] = (sz >> 16) as u8;
            r[4] = (sz >> 8) as u8;
            r[5] = sz as u8;
            // rc = TPM_RC_SUCCESS
            r[6] = 0;
            r[7] = 0;
            r[8] = 0;
            r[9] = 0;
            // TPM2B_DIGEST size = 8
            r[10] = 0x00;
            r[11] = 0x08;
            // random bytes
            r[12] = 0xDE;
            r[13] = 0xAD;
            r[14] = 0xBE;
            r[15] = 0xEF;
            r[16] = 0x01;
            r[17] = 0x02;
            r[18] = 0x03;
            r[19] = 0x04;
            Ok(r)
        }
    }

    fn smoke_tpm0_write_read_roundtrip() -> TestResult {
        use crate::devfs_bridge::{DevTpm0, TpmTransport};
        use alloc::sync::Arc;
        use narf_filesystem::FileOps;

        // Install mock transport
        crate::devfs_bridge::register_transport(Arc::new(GetRandomMock) as Arc<dyn TpmTransport>);

        let dev = DevTpm0::new();

        // Build a minimal GetRandom command (tag + size + CC + count)
        let mut cmd = alloc::vec![0u8; 12];
        cmd[0] = 0x80;
        cmd[1] = 0x01; // tag TPM_ST_NO_SESSIONS
        cmd[2] = 0;
        cmd[3] = 0;
        cmd[4] = 0;
        cmd[5] = 12; // size
        cmd[6] = 0;
        cmd[7] = 0;
        cmd[8] = 0x01;
        cmd[9] = 0x7B; // CC GetRandom
        cmd[10] = 0;
        cmd[11] = 8; // bytesRequested = 8

        let n = poll_once_sync(dev.write(0, &cmd)).and_then(|r| r.ok());
        if n != Some(12) {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("write did not return 12");
        }

        let mut buf = [0u8; 32];
        let n = poll_once_sync(dev.read(0, &mut buf)).and_then(|r| r.ok());
        if n != Some(20) {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("read did not return 20");
        }
        let expected = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        if buf[12..20] != expected {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("response payload mismatch");
        }
        crate::devfs_bridge::unregister_transport();
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/devfs", smoke_tpm0_write_read_roundtrip);

    /// Echo transport: returns the command bytes back verbatim.
    struct EchoTransport;
    impl crate::devfs_bridge::TpmTransport for EchoTransport {
        fn submit(&self, cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, ()> {
            Ok(cmd.to_vec())
        }
    }

    fn smoke_tpm0_poll_readiness_pending() -> TestResult {
        use crate::devfs_bridge::{DevTpm0, TpmTransport};
        use alloc::sync::Arc;
        use narf_filesystem::{FileOps, POLL_IN, POLL_OUT};

        crate::devfs_bridge::register_transport(Arc::new(EchoTransport) as Arc<dyn TpmTransport>);

        let dev = DevTpm0::new();

        // Before write: only POLL_OUT, not POLL_IN
        let before = dev.poll_readiness();
        if before & POLL_IN != 0 {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("POLL_IN should not be set before write");
        }
        if before & POLL_OUT == 0 {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("POLL_OUT should be set before write");
        }

        // Write a minimal valid command
        let mut cmd = alloc::vec![0u8; 10];
        cmd[0] = 0x80;
        cmd[1] = 0x01; // tag
        cmd[2] = 0;
        cmd[3] = 0;
        cmd[4] = 0;
        cmd[5] = 10; // size
                     // CC doesn't matter for EchoTransport
        let _ = poll_once_sync(dev.write(0, &cmd));

        // After write: both POLL_IN | POLL_OUT
        let after = dev.poll_readiness();
        if after & POLL_IN == 0 {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("POLL_IN should be set after write");
        }
        if after & POLL_OUT == 0 {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("POLL_OUT should be set after write");
        }

        crate::devfs_bridge::unregister_transport();
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/devfs", smoke_tpm0_poll_readiness_pending);

    /// Transport that records flush calls for inspection.
    static FLUSH_CALLS: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<u32>> =
        narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

    struct TrackingTransport;
    impl crate::devfs_bridge::TpmTransport for TrackingTransport {
        fn submit(&self, cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, ()> {
            // Detect TPM2_FlushContext (CC = 0x0165) and record handle
            if cmd.len() >= 14 {
                let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
                if cc == 0x0000_0165 {
                    let handle = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
                    FLUSH_CALLS.lock().push(handle);
                    // Return a success response
                    let mut r = alloc::vec![0u8; 10];
                    r[0] = 0x80;
                    r[1] = 0x01;
                    r[2] = 0;
                    r[3] = 0;
                    r[4] = 0;
                    r[5] = 10;
                    return Ok(r);
                }
            }
            // For TPM2_Load (CC = 0x0157): return response with transient handle 0x8000_0001
            if cmd.len() >= 10 {
                let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
                if cc == crate::tpm2::TPM_CC_LOAD {
                    let mut r = alloc::vec![0u8; 14];
                    r[0] = 0x80;
                    r[1] = 0x01;
                    r[2] = 0;
                    r[3] = 0;
                    r[4] = 0;
                    r[5] = 14;
                    // rc = 0 (success)
                    r[6] = 0;
                    r[7] = 0;
                    r[8] = 0;
                    r[9] = 0;
                    // objectHandle = 0x8000_0001 (transient)
                    r[10] = 0x80;
                    r[11] = 0x00;
                    r[12] = 0x00;
                    r[13] = 0x01;
                    return Ok(r);
                }
            }
            Ok(alloc::vec![0u8; 10])
        }
    }

    fn smoke_tpmrm0_flush_on_drop() -> TestResult {
        use crate::devfs_bridge::{DevTpmRm0, TpmTransport};
        use alloc::sync::Arc;
        use narf_filesystem::FileOps;

        // Reset flush call tracker
        FLUSH_CALLS.lock().clear();

        crate::devfs_bridge::register_transport(
            Arc::new(TrackingTransport) as Arc<dyn TpmTransport>
        );

        {
            let dev = DevTpmRm0::new();

            // Send a TPM2_Load command — the response will contain handle 0x8000_0001
            let mut cmd = alloc::vec![0u8; 10];
            cmd[0] = 0x80;
            cmd[1] = 0x01;
            cmd[2] = 0;
            cmd[3] = 0;
            cmd[4] = 0;
            cmd[5] = 10;
            // CC = TPM_CC_LOAD = 0x0157
            cmd[6] = 0x00;
            cmd[7] = 0x00;
            cmd[8] = 0x01;
            cmd[9] = 0x57;
            let _ = poll_once_sync(dev.write(0, &cmd));

            // DevTpmRm0 drops here → flush_all_transients → TPM2_FlushContext(0x8000_0001)
        }

        let calls = FLUSH_CALLS.lock().clone();
        crate::devfs_bridge::unregister_transport();

        if !calls.contains(&0x8000_0001) {
            return TestResult::Fail("FlushContext was not called for handle 0x8000_0001");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/devfs", smoke_tpmrm0_flush_on_drop);

    // ── sysfs_bridge smoke tests ──────────────────────────────────────

    /// Null transport: always fails. Used to verify static attributes
    /// (version, enabled, active) that don't require a live TPM.
    #[allow(dead_code)]
    struct NullTransport;
    impl crate::devfs_bridge::TpmTransport for NullTransport {
        fn submit(&self, _cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, ()> {
            Err(())
        }
    }

    fn smoke_sysfs_tpm_version_major() -> TestResult {
        use crate::devfs_bridge::TpmTransport;
        use alloc::sync::Arc;

        // register_sysfs_tpm0 calls class_register which is idempotent;
        // the kobject tree allows repeated attribute additions (noop on dup).
        let t = Arc::new(NullTransport) as Arc<dyn TpmTransport>;
        crate::sysfs_bridge::register_sysfs_tpm0(t);

        // Read back the static attribute via the sysfs kobject.
        let class_tpm = narf_filesystem::class_register("tpm");
        let tpm0 = narf_filesystem::class_device_register(class_tpm, "tpm0");

        let major = tpm0.attr_show("tpm_version_major");
        let minor = tpm0.attr_show("tpm_version_minor");

        if major.as_deref() != Some("2\n") {
            return TestResult::Fail("tpm_version_major != '2\\n'");
        }
        if minor.as_deref() != Some("0\n") {
            return TestResult::Fail("tpm_version_minor != '0\\n'");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/sysfs", smoke_sysfs_tpm_version_major);

    /// PCR transport: returns a canned PCR_Read response with 20-byte
    /// SHA-1 and 32-byte SHA-256 digests (all-zeros).
    #[allow(dead_code)]
    struct PcrTransport;
    impl crate::devfs_bridge::TpmTransport for PcrTransport {
        fn submit(&self, cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, ()> {
            if cmd.len() < 10 {
                return Err(());
            }
            let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
            if cc == crate::tpm2::TPM_CC_PCR_READ {
                // Determine digest size from the algorithm in the command.
                // PCR_Read command layout Part 3 §22.4:
                // header(10) + TPML_PCR_SELECTION: count(4) + hashAlg(2) +
                // sizeofSelect(1) + pcrSelect(3)
                let alg = if cmd.len() >= 16 {
                    u16::from_be_bytes([cmd[14], cmd[15]])
                } else {
                    0x000B // default SHA-256
                };
                let digest_size = if alg == 0x0004 { 20usize } else { 32usize };

                // Build response:
                // header(10) + pcrUpdateCounter(4) +
                // TPML_PCR_SELECTION: count(4)+hashAlg(2)+sos(1)+bitmap(3) +
                // TPML_DIGEST: count(4) + TPM2B_DIGEST: size(2)+bytes(digest_size)
                let body_len = 4 + (4 + 2 + 1 + 3) + (4 + 2 + digest_size);
                let total = 10 + body_len;
                let mut r = alloc::vec![0u8; total];
                // header
                r[0] = 0x80;
                r[1] = 0x01;
                let sz = total as u32;
                r[2] = (sz >> 24) as u8;
                r[3] = (sz >> 16) as u8;
                r[4] = (sz >> 8) as u8;
                r[5] = sz as u8;
                // rc = 0
                r[6] = 0;
                r[7] = 0;
                r[8] = 0;
                r[9] = 0;
                let mut p = 10usize;
                // pcrUpdateCounter = 0
                p += 4;
                // TPML_PCR_SELECTION count = 1
                r[p] = 0;
                r[p + 1] = 0;
                r[p + 2] = 0;
                r[p + 3] = 1;
                p += 4;
                // hashAlg
                r[p] = (alg >> 8) as u8;
                r[p + 1] = alg as u8;
                p += 2;
                // sizeofSelect = 3
                r[p] = 3;
                p += 1;
                // pcrSelect = 3 bytes (all zeros, doesn't matter for parsing)
                p += 3;
                // TPML_DIGEST count = 1
                r[p] = 0;
                r[p + 1] = 0;
                r[p + 2] = 0;
                r[p + 3] = 1;
                p += 4;
                // TPM2B_DIGEST size
                r[p] = (digest_size >> 8) as u8;
                r[p + 1] = digest_size as u8;
                p += 2;
                // digest bytes = all zeros (already zeroed)
                let _ = p; // suppress unused warning
                return Ok(r);
            }
            Err(())
        }
    }

    fn smoke_sysfs_pcrs_format() -> TestResult {
        use crate::devfs_bridge::TpmTransport;
        use alloc::sync::Arc;

        let t = Arc::new(PcrTransport) as Arc<dyn TpmTransport>;
        crate::sysfs_bridge::register_sysfs_tpm0(t);

        let class_tpm = narf_filesystem::class_register("tpm");
        let tpm0 = narf_filesystem::class_device_register(class_tpm, "tpm0");

        let pcrs = match tpm0.attr_show("pcrs") {
            Some(s) => s,
            None => return TestResult::Fail("pcrs attribute missing"),
        };

        if !pcrs.starts_with("PCR-00:") {
            return TestResult::Fail("pcrs does not start with PCR-00:");
        }
        if !pcrs.contains("(SHA-1)") {
            return TestResult::Fail("pcrs missing '(SHA-1)' label");
        }
        if !pcrs.contains("(SHA-256)") {
            return TestResult::Fail("pcrs missing '(SHA-256)' label");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/sysfs", smoke_sysfs_pcrs_format);

    /// Manufacturer transport: returns 0x494E4643 ("INFC") for PT_MANUFACTURER.
    #[allow(dead_code)]
    struct MfrTransport;
    impl crate::devfs_bridge::TpmTransport for MfrTransport {
        fn submit(&self, cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, ()> {
            if cmd.len() < 10 {
                return Err(());
            }
            let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
            if cc == crate::tpm2::TPM_CC_GET_CAPABILITY {
                // Build GetCapability response with value 0x494E4643 ("INFC")
                // Body: moreData(1) + cap(4) + count(4) + tag(4) + value(4)
                let body = 1 + 4 + 4 + 4 + 4; // 17 bytes
                let total = 10 + body;
                let mut r = alloc::vec![0u8; total];
                r[0] = 0x80;
                r[1] = 0x01;
                let sz = total as u32;
                r[2] = (sz >> 24) as u8;
                r[3] = (sz >> 16) as u8;
                r[4] = (sz >> 8) as u8;
                r[5] = sz as u8;
                // rc = 0
                r[6] = 0;
                r[7] = 0;
                r[8] = 0;
                r[9] = 0;
                let mut p = 10usize;
                // moreData = 0
                r[p] = 0;
                p += 1;
                // capabilityCode = TPM_CAP_TPM_PROPERTIES = 6
                r[p] = 0;
                r[p + 1] = 0;
                r[p + 2] = 0;
                r[p + 3] = 6;
                p += 4;
                // count = 1
                r[p] = 0;
                r[p + 1] = 0;
                r[p + 2] = 0;
                r[p + 3] = 1;
                p += 4;
                // property tag = PT_MANUFACTURER = 0x105
                r[p] = 0;
                r[p + 1] = 0;
                r[p + 2] = 0x01;
                r[p + 3] = 0x05;
                p += 4;
                // value = 0x494E4643 ("INFC")
                r[p] = 0x49;
                r[p + 1] = 0x4E;
                r[p + 2] = 0x46;
                r[p + 3] = 0x43;
                return Ok(r);
            }
            Err(())
        }
    }

    fn smoke_sysfs_manufacturer_ascii() -> TestResult {
        use crate::devfs_bridge::TpmTransport;
        use alloc::sync::Arc;

        let t = Arc::new(MfrTransport) as Arc<dyn TpmTransport>;
        crate::sysfs_bridge::register_sysfs_tpm0(t);

        let class_tpm = narf_filesystem::class_register("tpm");
        let tpm0 = narf_filesystem::class_device_register(class_tpm, "tpm0");

        let mfr = match tpm0.attr_show("manufacturer") {
            Some(s) => s,
            None => return TestResult::Fail("manufacturer attribute missing"),
        };

        // Should be "INFC\n"
        if !mfr
            .trim_end_matches('\n')
            .chars()
            .all(|c| c.is_ascii_graphic() || c == ' ')
        {
            return TestResult::Fail("manufacturer value contains non-printable chars");
        }
        if mfr.trim_end_matches('\n').len() != 4 {
            return TestResult::Fail("manufacturer value is not 4 chars");
        }
        if !mfr.starts_with("INFC") {
            return TestResult::Fail("manufacturer should be 'INFC'");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/sysfs", smoke_sysfs_manufacturer_ascii);

    /// GetCapability transport for the `owned` fixture: answers
    /// `TPM_PT_PERMANENT` with a value the fixture controls, so
    /// each TPMA_PERMANENT bit can be exercised in isolation.
    static PERMANENT_VALUE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

    struct PermanentTransport;
    impl crate::devfs_bridge::TpmTransport for PermanentTransport {
        fn submit(&self, cmd: &[u8]) -> Result<alloc::vec::Vec<u8>, ()> {
            if cmd.len() < 10 {
                return Err(());
            }
            let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
            if cc != crate::tpm2::TPM_CC_GET_CAPABILITY {
                return Err(());
            }
            // Response layout (mirrors MfrTransport's): header(10) +
            // moreData(1) + capability(4) + count(4) + tag(4) +
            // value(4); read_property extracts tag at body[9..13]
            // and value at body[13..17].
            let total = 10 + 1 + 4 + 4 + 4 + 4;
            let mut r = alloc::vec![0u8; total];
            r[0] = 0x80;
            r[1] = 0x01;
            r[2..6].copy_from_slice(&(total as u32).to_be_bytes());
            // capability = TPM_CAP_TPM_PROPERTIES (6)
            r[14] = 6;
            // count = 1
            r[18] = 1;
            // property tag = PT_PERMANENT (0x0000_0200, variable
            // group — corrected from 0x10E in #941)
            r[21] = 0x02;
            r[22] = 0x00;
            // value = the fixture-controlled TPMA_PERMANENT
            let v = PERMANENT_VALUE.load(core::sync::atomic::Ordering::SeqCst);
            r[23..27].copy_from_slice(&v.to_be_bytes());
            Ok(r)
        }
    }

    fn smoke_sysfs_owned_reflects_owner_auth_bit() -> TestResult {
        use crate::devfs_bridge::TpmTransport;
        use alloc::sync::Arc;
        use core::sync::atomic::Ordering;

        let t = Arc::new(PermanentTransport) as Arc<dyn TpmTransport>;
        crate::sysfs_bridge::register_sysfs_tpm0(t);

        let class_tpm = narf_filesystem::class_register("tpm");
        let tpm0 = narf_filesystem::class_device_register(class_tpm, "tpm0");

        // TPMA_PERMANENT (Part 2 §10.11): ownerAuthSet is bit 0,
        // endorsementAuthSet bit 1, lockoutAuthSet bit 2. `owned`
        // must track bit 0 only. The pre-#940 code tested bit 1
        // under a comment claiming bit 2, so it reported the
        // endorsement hierarchy's auth state — the 0b010 case is
        // the one that catches it.
        let cases: [(u32, &str); 5] = [
            (0b000, "0\n"),
            (0b001, "1\n"),
            (0b010, "0\n"),
            (0b100, "0\n"),
            (0b111, "1\n"),
        ];
        for (value, want) in cases {
            PERMANENT_VALUE.store(value, Ordering::SeqCst);
            match tpm0.attr_show("owned") {
                Some(s) if s == want => {}
                _ => {
                    return TestResult::Fail(
                        "owned does not reflect TPMA_PERMANENT bit 0 (ownerAuthSet)",
                    );
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/tpm/sysfs",
        smoke_sysfs_owned_reflects_owner_auth_bit
    );

    // ── Per-open state fixtures (#940) ─────────────────────────────
    //
    // The registered nodes are prototypes; `sys_open` clones them
    // per fd through `FileOps::open_instance`. These fixtures pin
    // the two contracts that follow: response state is per-fd, and
    // the RM node's FlushContext-on-close fires at the owning fd's
    // close only.

    fn smoke_tpm0_open_instance_state_isolation() -> TestResult {
        use crate::devfs_bridge::{DevTpm0, TpmTransport};
        use alloc::sync::Arc;
        use narf_filesystem::FileOps;

        crate::devfs_bridge::register_transport(Arc::new(GetRandomMock) as Arc<dyn TpmTransport>);

        let proto = DevTpm0::new();
        let (fd_a, fd_b) = match (proto.open_instance(), proto.open_instance()) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                crate::devfs_bridge::unregister_transport();
                return TestResult::Fail("DevTpm0::open_instance returned None");
            }
        };
        if Arc::ptr_eq(&fd_a, &fd_b) {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("open_instance returned the same instance twice");
        }

        // GetRandom command, as in smoke_tpm0_write_read_roundtrip.
        let mut cmd = alloc::vec![0u8; 12];
        cmd[0] = 0x80;
        cmd[1] = 0x01; // tag TPM_ST_NO_SESSIONS
        cmd[5] = 12; // size
        cmd[8] = 0x01;
        cmd[9] = 0x7B; // CC GetRandom
        cmd[11] = 8; // bytesRequested = 8

        let n = poll_once_sync(fd_a.write(0, &cmd)).and_then(|r| r.ok());
        if n != Some(12) {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("write on fd A did not return 12");
        }
        // fd B must not observe fd A's pending response: with no
        // response of its own, its read is EOF (0), exactly as a
        // fresh Linux tpm fd behaves before any write.
        let mut buf_b = [0u8; 32];
        let nb = poll_once_sync(fd_b.read(0, &mut buf_b)).and_then(|r| r.ok());
        if nb != Some(0) {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("fd B observed fd A's pending response");
        }
        // fd A reads its own response back.
        let mut buf_a = [0u8; 32];
        let na = poll_once_sync(fd_a.read(0, &mut buf_a)).and_then(|r| r.ok());
        crate::devfs_bridge::unregister_transport();
        if na != Some(20) {
            return TestResult::Fail("fd A did not read its 20-byte response");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/tpm/devfs",
        smoke_tpm0_open_instance_state_isolation
    );

    fn smoke_tpmrm0_open_instance_flushes_only_own_handles() -> TestResult {
        use crate::devfs_bridge::{DevTpmRm0, TpmTransport};
        use alloc::sync::Arc;
        use narf_filesystem::FileOps;

        FLUSH_CALLS.lock().clear();
        crate::devfs_bridge::register_transport(
            Arc::new(TrackingTransport) as Arc<dyn TpmTransport>
        );

        let proto = DevTpmRm0::new();
        let (fd_a, fd_b) = match (proto.open_instance(), proto.open_instance()) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                crate::devfs_bridge::unregister_transport();
                return TestResult::Fail("DevTpmRm0::open_instance returned None");
            }
        };

        // TPM2_Load on fd A — TrackingTransport answers with
        // transient handle 0x8000_0001 (as in
        // smoke_tpmrm0_flush_on_drop), which fd A now tracks.
        let mut cmd = alloc::vec![0u8; 10];
        cmd[0] = 0x80;
        cmd[1] = 0x01;
        cmd[5] = 10;
        cmd[8] = 0x01;
        cmd[9] = 0x57; // CC = TPM_CC_LOAD
        let _ = poll_once_sync(fd_a.write(0, &cmd));

        // Closing fd B (which allocated nothing) must not flush
        // fd A's handle — under the pre-#940 shared-node model the
        // single instance's Drop was the only flush point, so this
        // distinction did not exist.
        drop(fd_b);
        if FLUSH_CALLS.lock().contains(&0x8000_0001) {
            crate::devfs_bridge::unregister_transport();
            return TestResult::Fail("closing fd B flushed fd A's transient handle");
        }
        // Closing fd A flushes exactly its own handle.
        drop(fd_a);
        let calls = FLUSH_CALLS.lock().clone();
        crate::devfs_bridge::unregister_transport();
        if !calls.contains(&0x8000_0001) {
            return TestResult::Fail("closing fd A did not flush its transient handle");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/tpm/devfs",
        smoke_tpmrm0_open_instance_flushes_only_own_handles
    );
}
