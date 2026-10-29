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
use crate::tpm2::nv::{NvIndex, NARF_SUSPEND_EPOCH_NV, NV_ATTR_PLATFORM_RW};
use crate::tpm2::{
    TPM_ALG_SHA256, TPM_CAP_TPM_PROPERTIES, TPM_CC_DICTIONARY_ATTACK_LOCK_RESET,
    TPM_CC_DICTIONARY_ATTACK_PARAMETERS, TPM_CC_NV_INCREMENT, TPM_CC_POLICY_GET_DIGEST,
    TPM_PT_LOCKOUT_COUNTER, TPM_RC_AUTH_FAIL, TPM_RC_BAD_AUTH, TPM_RC_FAILURE, TPM_RC_HANDLE,
    TPM_RC_LOCKOUT, TPM_RC_NV_DEFINED, TPM_RC_NV_UNINITIALIZED, TPM_RC_POLICY_FAIL, TPM_RC_SUCCESS,
    TPM_RH_NULL, TPM_RH_PLATFORM, TPM_RS_PW, TPM_SE_POLICY, TPM_SE_TRIAL, TPM_SU_CLEAR,
    TPM_SU_STATE,
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

// ── Lifecycle: DA builder byte pins (#1003) ─────────────────────

fn smoke_fixture_da_builder_byte_pins() -> TestResult {
    if TPM_CC_DICTIONARY_ATTACK_LOCK_RESET != 0x0000_0139
        || TPM_CC_DICTIONARY_ATTACK_PARAMETERS != 0x0000_013A
    {
        return TestResult::Fail("DA command code constants are wrong");
    }
    // LockReset: SESSIONS header, lockout handle, one empty
    // password session, nothing else.
    let cmd = cmds::dictionary_attack_lock_reset();
    if cmd.len() != 10 + 4 + 9 {
        return TestResult::Fail("lock reset frame size is wrong");
    }
    let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
    let handle = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
    if cc != TPM_CC_DICTIONARY_ATTACK_LOCK_RESET || handle != crate::tpm2::TPM_RH_LOCKOUT {
        return TestResult::Fail("lock reset frame's code/handle are wrong");
    }
    // Parameters: the three u32s trail the session area in
    // declaration order (newMaxTries, newRecoveryTime,
    // lockoutRecovery).
    let cmd = cmds::dictionary_attack_parameters(3, 600, 900);
    if cmd.len() != 10 + 4 + 9 + 12 {
        return TestResult::Fail("DA parameters frame size is wrong");
    }
    let tail = &cmd[cmd.len() - 12..];
    let fields: Vec<u32> = tail
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    if fields != alloc::vec![3, 600, 900] {
        return TestResult::Fail("DA parameters fields are wrong or misordered");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/tpm/fixture", smoke_fixture_da_builder_byte_pins);

// ── Lifecycle: Startup / Shutdown sequencing (#1003) ────────────

fn smoke_fixture_startup_state_sequencing() -> TestResult {
    let t = Arc::new(FixtureTpm::new());
    // No saved state exists yet: a STATE startup is a value
    // error (Part 3 §9.3), a CLEAR startup succeeds.
    let resp = t.submit(&cmds::startup(TPM_SU_STATE)).unwrap_or_default();
    if rc(&resp) != crate::tpm2::TPM_RC_VALUE {
        return TestResult::Fail("STATE startup without saved state was not TPM_RC_VALUE");
    }
    if ok_submit(&t, &cmds::startup(TPM_SU_CLEAR)).is_err() {
        return TestResult::Fail("CLEAR startup failed");
    }
    // Already started: any further Startup is a value error —
    // the production fold treats it as "already started".
    let resp = t.submit(&cmds::startup(TPM_SU_CLEAR)).unwrap_or_default();
    if rc(&resp) != crate::tpm2::TPM_RC_VALUE {
        return TestResult::Fail("second Startup was not TPM_RC_VALUE");
    }
    // An orderly STATE cycle preserves the PCRs.
    if ok_submit(&t, &cmds::pcr_extend_sha256(7, &[0x99; 32])).is_err() {
        return TestResult::Fail("PCR extend failed");
    }
    let before = t.pcr(7);
    if ok_submit(&t, &cmds::shutdown(TPM_SU_STATE)).is_err() {
        return TestResult::Fail("STATE shutdown failed");
    }
    if t.is_started() {
        return TestResult::Fail("TPM still started after Shutdown");
    }
    let resp = t.submit(&cmds::get_random(8)).unwrap_or_default();
    if rc(&resp) != crate::tpm2::TPM_RC_INITIALIZE {
        return TestResult::Fail("command after Shutdown was not TPM_RC_INITIALIZE");
    }
    if ok_submit(&t, &cmds::startup(TPM_SU_STATE)).is_err() {
        return TestResult::Fail("STATE startup after STATE shutdown failed");
    }
    if t.pcr(7) != before {
        return TestResult::Fail("PCRs did not survive the STATE cycle");
    }
    // A CLEAR shutdown arms only a CLEAR startup, which resets.
    if ok_submit(&t, &cmds::shutdown(TPM_SU_CLEAR)).is_err() {
        return TestResult::Fail("CLEAR shutdown failed");
    }
    let resp = t.submit(&cmds::startup(TPM_SU_STATE)).unwrap_or_default();
    if rc(&resp) != crate::tpm2::TPM_RC_VALUE {
        return TestResult::Fail("STATE startup after CLEAR shutdown was not TPM_RC_VALUE");
    }
    if ok_submit(&t, &cmds::startup(TPM_SU_CLEAR)).is_err() {
        return TestResult::Fail("CLEAR startup after CLEAR shutdown failed");
    }
    if t.pcr(7) != [0u8; 32] {
        return TestResult::Fail("CLEAR startup did not reset the PCRs");
    }
    // Dirty power loss: the state saved by nobody is restored
    // for nobody.
    if ok_submit(&t, &cmds::pcr_extend_sha256(7, &[0x99; 32])).is_err() {
        return TestResult::Fail("PCR extend failed");
    }
    t.simulate_power_loss();
    let resp = t.submit(&cmds::startup(TPM_SU_STATE)).unwrap_or_default();
    if rc(&resp) != crate::tpm2::TPM_RC_VALUE {
        return TestResult::Fail("STATE startup after power loss was not TPM_RC_VALUE");
    }
    if ok_submit(&t, &cmds::startup(TPM_SU_CLEAR)).is_err() {
        return TestResult::Fail("CLEAR startup after power loss failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/tpm/fixture",
    smoke_fixture_startup_state_sequencing
);

// ── Lifecycle: dictionary-attack accounting (#1003) ─────────────

/// Rewrite the first (password) session of a built frame to
/// present `auth` as its HMAC field, at authorization-area
/// offset `auth_off` (right after the frame's handles). The
/// builders all present the empty value; staging an auth
/// failure — or a correct non-empty value — is a wire-level
/// act, so the fixture is exercised with the frame silicon
/// would see.
fn with_pw_auth(frame: &[u8], auth_off: usize, auth: &[u8]) -> Vec<u8> {
    let old_size = u32::from_be_bytes([
        frame[auth_off],
        frame[auth_off + 1],
        frame[auth_off + 2],
        frame[auth_off + 3],
    ]) as usize;
    let mut out = Vec::new();
    out.extend_from_slice(&frame[..auth_off]);
    out.extend_from_slice(&(9u32 + auth.len() as u32).to_be_bytes());
    out.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // nonce size
    out.push(0u8); // session attributes
    out.extend_from_slice(&(auth.len() as u16).to_be_bytes());
    out.extend_from_slice(auth);
    out.extend_from_slice(&frame[auth_off + 4 + old_size..]);
    let total = out.len() as u32;
    out[2..6].copy_from_slice(&total.to_be_bytes());
    out
}

fn smoke_fixture_da_accounting() -> TestResult {
    let t = started_fixture();
    // The epoch counter first, while hierarchy auths are still
    // empty: a wrong auth against a NO_DA index is BAD_AUTH and
    // is never counted (the counter's increments must never be
    // able to lock out resume).
    if ok_submit(&t, &NARF_SUSPEND_EPOCH_NV.define_space_cmd()).is_err() {
        return TestResult::Fail("epoch counter define failed");
    }
    let bad_increment = with_pw_auth(
        &cmds::nv_increment(NARF_SUSPEND_EPOCH_NV.handle),
        18,
        b"wrong",
    );
    let resp = t.submit(&bad_increment).unwrap_or_default();
    if rc(&resp) != TPM_RC_BAD_AUTH {
        return TestResult::Fail("wrong auth on a NO_DA index was not TPM_RC_BAD_AUTH");
    }
    if t.failed_tries() != 0 {
        return TestResult::Fail("a NO_DA failure was counted");
    }
    if ok_submit(&t, &cmds::nv_increment(NARF_SUSPEND_EPOCH_NV.handle)).is_err() {
        return TestResult::Fail("honest counter increment failed");
    }
    // Provision an owner auth and stage a threshold of 2.
    t.set_owner_auth(b"correct-horse");
    if ok_submit(&t, &cmds::dictionary_attack_parameters(2, 600, 600)).is_err() {
        return TestResult::Fail("DA parameters failed");
    }
    let wrong_primary = with_pw_auth(&cmds::create_primary_rsa_storage(), 14, b"wrong");
    let right_primary = with_pw_auth(&cmds::create_primary_rsa_storage(), 14, b"correct-horse");
    for want in 1..=2u32 {
        let resp = t.submit(&wrong_primary).unwrap_or_default();
        if rc(&resp) != TPM_RC_AUTH_FAIL {
            return TestResult::Fail("wrong owner auth was not TPM_RC_AUTH_FAIL");
        }
        if t.failed_tries() != want {
            return TestResult::Fail("failedTries did not increment per auth failure");
        }
    }
    // At the threshold the TPM is in lockout: even the correct
    // auth is refused, with TPM_RC_LOCKOUT — and the refusal
    // itself does not count further.
    let resp = t.submit(&right_primary).unwrap_or_default();
    if rc(&resp) != TPM_RC_LOCKOUT {
        return TestResult::Fail("correct auth in lockout was not TPM_RC_LOCKOUT");
    }
    if t.failed_tries() != 2 {
        return TestResult::Fail("a lockout refusal was counted");
    }
    // The accounting is readable through the production query
    // path: TPM_PT_LOCKOUT_COUNTER via GetCapability.
    let resp = match ok_submit(
        &t,
        &cmds::get_capability(TPM_CAP_TPM_PROPERTIES, TPM_PT_LOCKOUT_COUNTER, 1),
    ) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("lockout counter query failed"),
    };
    let envelope = match cmds::parse_get_capability_response(&resp) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("lockout counter response did not parse"),
    };
    match cmds::parse_tagged_properties(&envelope.data) {
        Ok(props) if props == alloc::vec![(TPM_PT_LOCKOUT_COUNTER, 2)] => {}
        _ => return TestResult::Fail("lockout counter property is not failedTries"),
    }
    // The lockout-authorized reset cancels the lockout.
    if ok_submit(&t, &cmds::dictionary_attack_lock_reset()).is_err() {
        return TestResult::Fail("lockout reset failed");
    }
    if t.failed_tries() != 0 {
        return TestResult::Fail("lockout reset did not zero failedTries");
    }
    if ok_submit(&t, &right_primary).is_err() {
        return TestResult::Fail("correct auth still refused after lockout reset");
    }
    // A *failed* lockout reset is itself a counted auth
    // failure: provision a lockout auth, then present the
    // wrong one through a rebuilt frame.
    t.set_lockout_auth(b"lockout-secret");
    let bad_reset = with_pw_auth(&cmds::dictionary_attack_lock_reset(), 14, b"wrong");
    let resp = t.submit(&bad_reset).unwrap_or_default();
    if rc(&resp) != TPM_RC_AUTH_FAIL {
        return TestResult::Fail("wrong lockout auth was not TPM_RC_AUTH_FAIL");
    }
    if t.failed_tries() != 1 {
        return TestResult::Fail("a failed lockout reset was not counted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/tpm/fixture", smoke_fixture_da_accounting);

// ── Lifecycle: Clear flushes the owner world (#1003) ────────────

fn smoke_fixture_clear_flushes_owner_world() -> TestResult {
    let t = started_fixture();
    // A sealed object, the owner-defined epoch counter, and a
    // platform-defined index walk into a Clear…
    let policy = match trial_policy(&t) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("trial policy failed"),
    };
    let primary = match primary(&t) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("create_primary failed"),
    };
    let created = match seal(&t, primary, &policy, &[0xAB; 32]) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("create sealed object failed"),
    };
    if ok_submit(&t, &NARF_SUSPEND_EPOCH_NV.define_space_cmd()).is_err()
        || ok_submit(&t, &cmds::nv_increment(NARF_SUSPEND_EPOCH_NV.handle)).is_err()
    {
        return TestResult::Fail("epoch counter provisioning failed");
    }
    const PLATFORM_IDX: u32 = 0x0150_00F0;
    let platform_desc = NvIndex::new(PLATFORM_IDX, 8, NV_ATTR_PLATFORM_RW);
    let mut define_frame = platform_desc.define_space_cmd();
    // The builder defines under the owner; re-target the frame
    // to define this one under the platform hierarchy.
    define_frame[10..14].copy_from_slice(&TPM_RH_PLATFORM.to_be_bytes());
    if ok_submit(&t, &define_frame).is_err() {
        return TestResult::Fail("platform index define failed");
    }
    if ok_submit(&t, &cmds::pcr_extend_sha256(3, &[0x77; 32])).is_err() {
        return TestResult::Fail("PCR extend failed");
    }
    // …after burning one DA failure, so the reset shows too.
    t.set_owner_auth(b"staged-owner");
    let wrong_primary = with_pw_auth(&cmds::create_primary_rsa_storage(), 14, b"wrong");
    let resp = t.submit(&wrong_primary).unwrap_or_default();
    if rc(&resp) != TPM_RC_AUTH_FAIL || t.failed_tries() != 1 {
        return TestResult::Fail("staged auth failure did not count");
    }
    if ok_submit(&t, &cmds::clear()).is_err() {
        return TestResult::Fail("Clear failed");
    }
    // The sealed blob is dead: its private half names a created
    // object the new seed never minted.
    let resp = t
        .submit(&cmds::load(
            primary,
            &created.out_private,
            &created.out_public,
        ))
        .unwrap_or_default();
    if rc(&resp) != TPM_RC_FAILURE {
        return TestResult::Fail("sealed blob loaded after Clear");
    }
    // The owner-defined counter is flushed; the platform index
    // survives (defined, still unwritten).
    let resp = t
        .submit(&cmds::nv_read(NARF_SUSPEND_EPOCH_NV.handle, 8, 0))
        .unwrap_or_default();
    if rc(&resp) != TPM_RC_HANDLE {
        return TestResult::Fail("owner NV index survived Clear");
    }
    let resp = t
        .submit(&cmds::nv_read(PLATFORM_IDX, 8, 0))
        .unwrap_or_default();
    if rc(&resp) != TPM_RC_NV_UNINITIALIZED {
        return TestResult::Fail("platform NV index did not survive Clear");
    }
    // PCRs, the DA counter, and the hierarchy auths are reset:
    // the provisioned owner auth is gone, so the empty-auth
    // primary ceremony works again.
    if t.pcr(3) != [0u8; 32] {
        return TestResult::Fail("Clear did not reset the PCRs");
    }
    if t.failed_tries() != 0 {
        return TestResult::Fail("Clear did not reset the DA counter");
    }
    if ok_submit(&t, &cmds::create_primary_rsa_storage()).is_err() {
        return TestResult::Fail("hierarchy auths were not zeroed by Clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/tpm/fixture",
    smoke_fixture_clear_flushes_owner_world
);
