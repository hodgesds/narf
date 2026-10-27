//! Conversation fixtures for [`crate::fixture_tpm::FixtureTpm`]
//! and byte pins for the sealing-minimum codec additions
//! (#1002).
//!
//! The centre of gravity is the policy-digest independence pin:
//! the expected `authPolicy` is computed *in this file*, from
//! the Part 3 §23.7 formula over PCR values read through the
//! production PCR_Read path — never by asking the fixture's
//! session machinery — so the fixture and the formula are
//! checked against each other, not against themselves (the
//! #1068 agreement failure is the thing being defended
//! against).

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::devfs_bridge::TpmTransport;
use crate::fixture_tpm::{sha256, started_fixture, FixtureTpm};
use crate::tpm2::commands as cmds;
use crate::tpm2::nv::NARF_SUSPEND_EPOCH_NV;
use crate::tpm2::{
    TPM_ALG_SHA256, TPM_CC_NV_INCREMENT, TPM_CC_POLICY_GET_DIGEST, TPM_RC_NV_DEFINED,
    TPM_RC_NV_UNINITIALIZED, TPM_RC_POLICY_FAIL, TPM_RC_SUCCESS, TPM_RH_NULL, TPM_SE_POLICY,
    TPM_SE_TRIAL,
};

const POLICY_MASK: [u8; 3] = [0xFF, 0x06, 0x00];
const POLICY_PCRS: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 9, 10];

fn rc(resp: &[u8]) -> u32 {
    cmds::response_rc(resp).unwrap_or(u32::MAX)
}

fn ok_submit(t: &Arc<FixtureTpm>, cmd: &[u8]) -> Result<Vec<u8>, &'static str> {
    let resp = t.submit(cmd).map_err(|_| "transport error")?;
    if rc(&resp) != TPM_RC_SUCCESS {
        return Err("command did not succeed");
    }
    Ok(resp)
}

/// The trial-session policy computation, driven end to end
/// through the production builders: returns the authPolicy for
/// the fixture's current PCR state.
fn trial_policy(t: &Arc<FixtureTpm>) -> Result<[u8; 32], &'static str> {
    let resp = ok_submit(
        t,
        &cmds::start_auth_session(
            TPM_RH_NULL,
            TPM_RH_NULL,
            &[7u8; 32],
            &[],
            TPM_SE_TRIAL,
            TPM_ALG_SHA256,
        ),
    )?;
    let (session, _) =
        cmds::parse_start_auth_session_response(&resp).map_err(|_| "session parse")?;
    let resp = ok_submit(t, &cmds::pcr_read(TPM_ALG_SHA256, &POLICY_MASK))?;
    let read = cmds::parse_pcr_read_response(&resp).map_err(|_| "pcr_read parse")?;
    if read.digests.len() != POLICY_PCRS.len() {
        return Err("pcr_read digest count");
    }
    let mut concat = Vec::new();
    for d in &read.digests {
        concat.extend_from_slice(d);
    }
    let composite = sha256(&concat);
    ok_submit(
        t,
        &cmds::policy_pcr(session, &composite, &[(TPM_ALG_SHA256, &POLICY_MASK)]),
    )?;
    let resp = ok_submit(t, &cmds::policy_get_digest(session))?;
    let digest = cmds::parse_policy_get_digest_response(&resp).map_err(|_| "digest parse")?;
    let _ = t.submit(&cmds::flush_context(session));
    digest.try_into().map_err(|_| "digest length")
}

fn primary(t: &Arc<FixtureTpm>) -> Result<u32, &'static str> {
    let resp = ok_submit(t, &cmds::create_primary_rsa_storage())?;
    let (handle, _) = cmds::parse_create_primary_response(&resp).map_err(|_| "primary parse")?;
    Ok(handle)
}

fn seal(
    t: &Arc<FixtureTpm>,
    primary: u32,
    policy: &[u8; 32],
    data: &[u8],
) -> Result<cmds::CreateOutputs, &'static str> {
    let template = crate::tpm2::objects::keyedhash_seal_template(policy);
    let resp = ok_submit(t, &cmds::create_sealed_object(primary, data, &template))?;
    cmds::parse_create_response(&resp).map_err(|_| "create parse")
}

fn load_and_unseal(
    t: &Arc<FixtureTpm>,
    primary: u32,
    created: &cmds::CreateOutputs,
) -> Result<Vec<u8>, u32> {
    let resp = t
        .submit(&cmds::load(
            primary,
            &created.out_private,
            &created.out_public,
        ))
        .unwrap_or_default();
    if rc(&resp) != TPM_RC_SUCCESS {
        return Err(rc(&resp));
    }
    let (object, _) = cmds::parse_load_response(&resp).map_err(|_| u32::MAX)?;
    let resp = t
        .submit(&cmds::start_auth_session(
            TPM_RH_NULL,
            TPM_RH_NULL,
            &[9u8; 32],
            &[],
            TPM_SE_POLICY,
            TPM_ALG_SHA256,
        ))
        .unwrap_or_default();
    let (session, _) = cmds::parse_start_auth_session_response(&resp).map_err(|_| u32::MAX)?;
    let resp = t
        .submit(&cmds::policy_pcr(
            session,
            &[],
            &[(TPM_ALG_SHA256, &POLICY_MASK)],
        ))
        .unwrap_or_default();
    if rc(&resp) != TPM_RC_SUCCESS {
        return Err(rc(&resp));
    }
    let resp = t
        .submit(&cmds::unseal_with_session(object, session))
        .unwrap_or_default();
    if rc(&resp) != TPM_RC_SUCCESS {
        return Err(rc(&resp));
    }
    cmds::parse_unseal_response(&resp).map_err(|_| u32::MAX)
}

// ── Builder byte pins ────────────────────────────────────────────

fn smoke_fixture_builder_byte_pins() -> TestResult {
    // PolicyGetDigest: NO_SESSIONS header + the one handle,
    // nothing else (Part 3 — the command has no parameters).
    let cmd = cmds::policy_get_digest(0x0200_0001);
    let want: [u8; 14] = [
        0x80, 0x01, // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0E, // size = 14
        0x00, 0x00, 0x01, 0x89, // TPM_CC_PolicyGetDigest
        0x02, 0x00, 0x00, 0x01, // session handle
    ];
    if cmd != want {
        return TestResult::Fail("policy_get_digest frame differs from the pinned bytes");
    }
    if TPM_CC_POLICY_GET_DIGEST != 0x0000_0189 {
        return TestResult::Fail("TPM_CC_POLICY_GET_DIGEST constant is wrong");
    }
    // NV_Increment: SESSIONS, index as both handles, one empty
    // password session in the authorization area.
    let cmd = cmds::nv_increment(0x0150_0003);
    let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
    if cc != TPM_CC_NV_INCREMENT || TPM_CC_NV_INCREMENT != 0x0000_0134 {
        return TestResult::Fail("nv_increment command code is wrong");
    }
    let auth_handle = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
    let nv_handle = u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]);
    if auth_handle != 0x0150_0003 || nv_handle != 0x0150_0003 {
        return TestResult::Fail("nv_increment handles are not (index, index)");
    }
    let total = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) as usize;
    if total != cmd.len() || total != 10 + 8 + 9 {
        return TestResult::Fail("nv_increment frame size is wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/tpm/fixture", smoke_fixture_builder_byte_pins);

// ── Policy digest: computed independently from the spec formula ─

fn smoke_fixture_policy_digest_matches_spec() -> TestResult {
    let t = started_fixture();
    // Give the PCR state some content first, so the composite is
    // not the all-zero trivial case.
    if ok_submit(&t, &cmds::pcr_extend_sha256(4, &[0x11; 32])).is_err()
        || ok_submit(&t, &cmds::pcr_extend_sha256(9, &[0x22; 32])).is_err()
    {
        return TestResult::Fail("PCR extends failed");
    }
    let via_session = match trial_policy(&t) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("trial policy computation failed"),
    };
    // Independent computation (Part 3 §23.7, eq. 19/20):
    // policy = H( 0^32 ‖ TPM_CC_PolicyPCR ‖ TPML_PCR_SELECTION ‖
    //             H(PCR values in selection order) )
    let mut concat = Vec::new();
    for pcr in POLICY_PCRS {
        concat.extend_from_slice(&t.pcr(pcr));
    }
    let composite = sha256(&concat);
    let mut tpml = Vec::new();
    tpml.extend_from_slice(&1u32.to_be_bytes());
    tpml.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    tpml.push(3u8);
    tpml.extend_from_slice(&POLICY_MASK);
    let mut input = Vec::new();
    input.extend_from_slice(&[0u8; 32]);
    input.extend_from_slice(&crate::tpm2::TPM_CC_POLICY_PCR.to_be_bytes());
    input.extend_from_slice(&tpml);
    input.extend_from_slice(&composite);
    let expected = sha256(&input);
    if via_session != expected {
        return TestResult::Fail("trial policy digest != the spec formula's digest");
    }
    if via_session == [0u8; 32] {
        return TestResult::Fail("policy digest is the zero digest (PolicyPCR did not fold)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/tpm/fixture",
    smoke_fixture_policy_digest_matches_spec
);

// ── Seal / unseal conversation ───────────────────────────────────

fn smoke_fixture_seal_unseal_round_trip() -> TestResult {
    let t = started_fixture();
    let policy = match trial_policy(&t) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("trial policy failed"),
    };
    let primary = match primary(&t) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create_primary failed"),
    };
    let secret: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0x5A);
    let created = match seal(&t, primary, &policy, &secret) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("create sealed object failed"),
    };
    match load_and_unseal(&t, primary, &created) {
        Ok(data) if data == secret => {}
        _ => return TestResult::Fail("unsealed data differs from the sealed secret"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/tpm/fixture", smoke_fixture_seal_unseal_round_trip);

fn smoke_fixture_pcr_mismatch_policy_fail() -> TestResult {
    let t = started_fixture();
    let policy = match trial_policy(&t) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("trial policy failed"),
    };
    let primary = match primary(&t) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create_primary failed"),
    };
    let created = match seal(&t, primary, &policy, &[0x77; 32]) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("create sealed object failed"),
    };
    if ok_submit(&t, &cmds::pcr_extend_sha256(0, &[0x01; 32])).is_err() {
        return TestResult::Fail("PCR extend failed");
    }
    match load_and_unseal(&t, primary, &created) {
        Err(got) if got == TPM_RC_POLICY_FAIL => {}
        Err(_) => return TestResult::Fail("PCR mismatch was not TPM_RC_POLICY_FAIL"),
        Ok(_) => return TestResult::Fail("PCR mismatch did not refuse the unseal"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/tpm/fixture",
    smoke_fixture_pcr_mismatch_policy_fail
);

fn smoke_fixture_tampered_public_fails_load() -> TestResult {
    let t = started_fixture();
    let policy = match trial_policy(&t) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("trial policy failed"),
    };
    let primary = match primary(&t) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create_primary failed"),
    };
    let created = match seal(&t, primary, &policy, &[0x42; 16]) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("create sealed object failed"),
    };
    let mut bad_public = created.out_public.clone();
    let n = bad_public.len();
    bad_public[n - 1] ^= 0x01;
    let resp = t
        .submit(&cmds::load(primary, &created.out_private, &bad_public))
        .unwrap_or_default();
    if rc(&resp) == TPM_RC_SUCCESS {
        return TestResult::Fail("load accepted a public area its blob was not minted for");
    }
    // The honest pair still loads.
    if ok_submit(
        &t,
        &cmds::load(primary, &created.out_private, &created.out_public),
    )
    .is_err()
    {
        return TestResult::Fail("honest load failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/tpm/fixture",
    smoke_fixture_tampered_public_fails_load
);

// ── NV counter discipline (Part 3 §31.13) ───────────────────────

fn smoke_fixture_nv_counter_lifecycle() -> TestResult {
    let t = started_fixture();
    let idx = NARF_SUSPEND_EPOCH_NV.handle;
    // Read of an undefined index: a failure, and specifically
    // not data.
    let resp = t.submit(&cmds::nv_read(idx, 8, 0)).unwrap_or_default();
    if rc(&resp) == TPM_RC_SUCCESS {
        return TestResult::Fail("read of an undefined NV index succeeded");
    }
    // Define: reads are now NV_UNINITIALIZED (WRITTEN clear),
    // even at size 0 — §31.13's explicit rule.
    if ok_submit(&t, &NARF_SUSPEND_EPOCH_NV.define_space_cmd()).is_err() {
        return TestResult::Fail("define of the epoch counter failed");
    }
    let resp = t.submit(&cmds::nv_read(idx, 8, 0)).unwrap_or_default();
    if rc(&resp) != TPM_RC_NV_UNINITIALIZED {
        return TestResult::Fail("unwritten counter did not read NV_UNINITIALIZED");
    }
    let resp = t.submit(&cmds::nv_read(idx, 0, 0)).unwrap_or_default();
    if rc(&resp) != TPM_RC_NV_UNINITIALIZED {
        return TestResult::Fail("size-0 read of an unwritten counter was not NV_UNINITIALIZED");
    }
    // Redefinition is refused.
    let resp = t
        .submit(&NARF_SUSPEND_EPOCH_NV.define_space_cmd())
        .unwrap_or_default();
    if rc(&resp) != TPM_RC_NV_DEFINED {
        return TestResult::Fail("redefinition was not NV_DEFINED");
    }
    // A counter changes only by increment: NV_Write is refused.
    let resp = t
        .submit(&cmds::nv_write(idx, &[0u8; 8], 0))
        .unwrap_or_default();
    if rc(&resp) == TPM_RC_SUCCESS {
        return TestResult::Fail("NV_Write changed a counter index");
    }
    // Two increments: the value reads back as 2, big-endian.
    if ok_submit(&t, &cmds::nv_increment(idx)).is_err()
        || ok_submit(&t, &cmds::nv_increment(idx)).is_err()
    {
        return TestResult::Fail("counter increment failed");
    }
    let resp = match ok_submit(&t, &cmds::nv_read(idx, 8, 0)) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("counter read failed after increments"),
    };
    match cmds::parse_nv_read_response(&resp) {
        Ok(v) if v.len() == 8 && v[..7] == [0u8; 7] && v[7] == 2 => {}
        _ => return TestResult::Fail("counter value is not 2 after two increments"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/tpm/fixture", smoke_fixture_nv_counter_lifecycle);

// ── Startup gating ───────────────────────────────────────────────

fn smoke_fixture_startup_gating() -> TestResult {
    let t = Arc::new(FixtureTpm::new());
    let resp = t.submit(&cmds::get_random(8)).unwrap_or_default();
    if rc(&resp) != crate::tpm2::TPM_RC_INITIALIZE {
        return TestResult::Fail("pre-Startup command was not TPM_RC_INITIALIZE");
    }
    if ok_submit(&t, &cmds::startup_clear()).is_err() {
        return TestResult::Fail("Startup failed");
    }
    if ok_submit(&t, &cmds::get_random(8)).is_err() {
        return TestResult::Fail("post-Startup GetRandom failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/tpm/fixture", smoke_fixture_startup_gating);
