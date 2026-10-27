//! End-to-end fixtures for the CTAP2 client, driven against the
//! independent fixture authenticator ([`crate::fixture_token`])
//! and against fully scripted pipes whose expected bytes are
//! hand-derived from the CTAP2 specification text (hex literals
//! in this file — never produced by the client's own encoder).
//!
//! Registered as kernel-test smokes (the tree's executed-test
//! currency; host `cargo test` binaries for crates on
//! narf-crypto cannot link narf-memory's kernel symbols — the
//! same reason narf-tpm's suite is smoke-shaped).
//!
//! Coverage map (issue #999's mandated pins):
//! (a) `smoke_scripted_make_credential_frame_is_byte_exact`
//! (b) `smoke_derive_matches_independent_hmac_computation`
//! (c) `smoke_wrong_pin_counts_retries_and_blocks`,
//!     `smoke_bad_pin_uv_auth_param_refused`
//! (d) `smoke_multi_credential_next_assertion`
//! (e) `smoke_malformed_inputs_are_clean_errors`
//! (f) `smoke_backup_token_distinct_credential_and_output`

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use narf_crypto::hkdf::hmac_sha256 as lib_hmac_sha256;
use narf_crypto::sha256::Sha256;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::cbor::Value;
use crate::client::{Client, GetAssertionParams, HmacSecretOutput, UserVerification};
use crate::ctaphid::{Channel, HidPipe, REPORT_LEN};
use crate::enroll::{
    derive_slot_output, enroll_token, enrollment_complete, DeriveParams, EnrollParams, PinSetup,
};
use crate::fixture_token::{FixturePipe, FixtureRng, FixtureToken};
use crate::status;
use crate::Error;

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !($cond) {
            return TestResult::Fail($msg);
        }
    };
}
macro_rules! check_eq {
    ($a:expr, $b:expr, $msg:expr) => {
        if $a != $b {
            return TestResult::Fail($msg);
        }
    };
}
macro_rules! try_ok {
    ($e:expr, $msg:expr) => {
        match $e {
            Ok(v) => v,
            Err(_) => return TestResult::Fail($msg),
        }
    };
}
macro_rules! try_some {
    ($e:expr, $msg:expr) => {
        match $e {
            Some(v) => v,
            None => return TestResult::Fail($msg),
        }
    };
}
macro_rules! try_err {
    ($e:expr, $msg:expr) => {
        match $e {
            Ok(_) => return TestResult::Fail($msg),
            Err(e) => e,
        }
    };
}

const RP_ID: &str = "suspend.narf";
const CDH: [u8; 32] = [0x42; 32];
const PIN: &[u8] = b"1234";

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

type FixtureClient = (Client<FixturePipe, FixtureRng>, Rc<RefCell<FixtureToken>>);

fn fixture_client(token_seed: u8) -> Result<FixtureClient, Error> {
    let token = Rc::new(RefCell::new(FixtureToken::new([token_seed; 32])));
    token.borrow_mut().set_auto_touch(2);
    let pipe = FixturePipe::new(token.clone());
    let client = Client::connect(pipe, FixtureRng::new([0xC1; 32]))?;
    Ok((client, token))
}

fn enroll_pin(
    client: &mut Client<FixturePipe, FixtureRng>,
    pin: &[u8],
) -> Result<crate::enroll::EnrolledToken, Error> {
    enroll_token(
        client,
        &EnrollParams {
            client_data_hash: CDH,
            rp_id: RP_ID,
            rp_name: Some("NARF Suspend"),
            user_id: &[1, 2, 3],
            user_name: Some("keys"),
            pin_setup: PinSetup::TouchAndPin(pin),
        },
    )
}

fn derive(
    client: &mut Client<FixturePipe, FixtureRng>,
    credential_id: &[u8],
    salt1: [u8; 32],
    salt2: Option<[u8; 32]>,
    pin: Option<&[u8]>,
) -> Result<HmacSecretOutput, Error> {
    derive_slot_output(
        client,
        &DeriveParams {
            client_data_hash: CDH,
            rp_id: RP_ID,
            credential_id,
            salt1,
            salt2,
            pin,
        },
    )
}

// ── (a) byte-exact scripted makeCredential ─────────────────────

#[derive(Default)]
struct ScriptedInner {
    responses: VecDeque<[u8; REPORT_LEN]>,
    written: Vec<[u8; REPORT_LEN]>,
}

#[derive(Clone, Default)]
struct ScriptedPipe {
    inner: Rc<RefCell<ScriptedInner>>,
}

impl ScriptedPipe {
    fn push_response(&self, cid: u32, cmd: u8, payload: &[u8]) {
        let mut rest = payload;
        let mut first = true;
        let mut seq = 0u8;
        loop {
            let mut r = [0u8; REPORT_LEN];
            r[0..4].copy_from_slice(&cid.to_be_bytes());
            if first {
                r[4] = 0x80 | cmd;
                r[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
                let n = core::cmp::min(rest.len(), 57);
                r[7..7 + n].copy_from_slice(&rest[..n]);
                rest = &rest[n..];
                first = false;
            } else {
                r[4] = seq;
                seq += 1;
                let n = core::cmp::min(rest.len(), 59);
                r[5..5 + n].copy_from_slice(&rest[..n]);
                rest = &rest[n..];
            }
            self.inner.borrow_mut().responses.push_back(r);
            if rest.is_empty() {
                break;
            }
        }
    }

    fn written(&self) -> Vec<[u8; REPORT_LEN]> {
        self.inner.borrow().written.clone()
    }
}

impl HidPipe for ScriptedPipe {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<(), Error> {
        self.inner.borrow_mut().written.push(*report);
        Ok(())
    }
    fn read_report(&mut self, out: &mut [u8; REPORT_LEN]) -> Result<(), Error> {
        self.inner
            .borrow_mut()
            .responses
            .pop_front()
            .map(|r| *out = r)
            .ok_or(Error::Timeout)
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    s.chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (p[1] as char).to_digit(16).unwrap_or(0) as u8;
            (hi << 4) | lo
        })
        .collect()
}

/// Reassemble a client message from raw reports starting at
/// `start`; returns (message, reports_consumed) or None on a
/// framing violation (bad sequence, short read).
fn reassemble(reports: &[[u8; REPORT_LEN]], start: usize) -> Option<(Vec<u8>, usize)> {
    let first = reports.get(start)?;
    let bcnt = u16::from_be_bytes([first[5], first[6]]) as usize;
    let mut msg = Vec::new();
    let take = core::cmp::min(bcnt, 57);
    msg.extend_from_slice(&first[7..7 + take]);
    let mut consumed = 1;
    while msg.len() < bcnt {
        let r = reports.get(start + consumed)?;
        if r[4] as usize != consumed - 1 {
            return None;
        }
        let need = bcnt - msg.len();
        let take = core::cmp::min(need, 59);
        msg.extend_from_slice(&r[5..5 + take]);
        consumed += 1;
    }
    Some((msg, consumed))
}

fn smoke_scripted_make_credential_frame_is_byte_exact() -> TestResult {
    // Client RNG: FixtureRng seeded [7;32]; the INIT nonce is the
    // first 8 bytes of SHA-256(seed ‖ counter=0 as u64 BE).
    let mut seed_block_input = Vec::new();
    seed_block_input.extend_from_slice(&[7u8; 32]);
    seed_block_input.extend_from_slice(&0u64.to_be_bytes());
    let nonce = sha256(&seed_block_input)[..8].to_vec();

    let pipe = ScriptedPipe::default();
    // INIT response: nonce echo | cid 0x0A0B0C0D | proto 2 |
    // v1.0.0 | caps = CBOR.
    let mut init_resp = nonce.clone();
    init_resp.extend_from_slice(&unhex("0A0B0C0D 02 01 00 00 02"));
    pipe.push_response(0xFFFF_FFFF, 0x06, &init_resp);
    // getInfo response CBOR, hand-encoded (CTAP2 §6.1, RFC 8949
    // canonical order): {1:["FIDO_2_0"], 2:["hmac-secret"],
    // 3:h'000102…0F', 4:{"clientPin":false}, 5:1200, 6:[1]}
    let info_cbor = unhex(
        "A6 01 81 68 4649444F5F325F30
         02 81 6B 686D61632D736563726574
         03 50 000102030405060708090A0B0C0D0E0F
         04 A1 69 636C69656E7450696E F4
         05 19 04B0
         06 81 01",
    );
    let mut info_resp = alloc::vec![0x00];
    info_resp.extend_from_slice(&info_cbor);
    pipe.push_response(0x0A0B0C0D, 0x10, &info_resp);
    // makeCredential response: {1:"none", 2:authData, 3:{}}.
    // authData = rpIdHash | flags 0x41 (UP|AT) | count 0 |
    // aaguid 0x22×16 | credIdLen 4 | DEADBEEF | COSE key
    // {1:2, 3:-7, -1:1, -2:h'33×32', -3:h'44×32'}.
    let mut auth = Vec::new();
    auth.extend_from_slice(&sha256(RP_ID.as_bytes()));
    auth.push(0x41);
    auth.extend_from_slice(&0u32.to_be_bytes());
    auth.extend_from_slice(&[0x22; 16]);
    auth.extend_from_slice(&4u16.to_be_bytes());
    auth.extend_from_slice(&unhex("DEADBEEF"));
    auth.extend_from_slice(&unhex("A5 01 02 03 26 20 01 21 58 20"));
    auth.extend_from_slice(&[0x33; 32]);
    auth.extend_from_slice(&unhex("22 58 20"));
    auth.extend_from_slice(&[0x44; 32]);
    check_eq!(auth.len(), 136, "scripted authData length");
    let mut mc_resp = unhex("00 A3 01 64 6E6F6E65 02 58 88");
    mc_resp.extend_from_slice(&auth);
    mc_resp.extend_from_slice(&unhex("03 A0"));
    pipe.push_response(0x0A0B0C0D, 0x10, &mc_resp);

    let mut client = try_ok!(
        Client::connect(pipe.clone(), FixtureRng::new([7u8; 32])),
        "connect over scripted pipe"
    );
    let info = try_ok!(client.get_info(), "getInfo");
    check!(
        info.versions.len() == 1 && info.versions[0] == "FIDO_2_0",
        "versions"
    );
    check!(
        info.supports_extension("hmac-secret"),
        "hmac-secret advertised"
    );
    check_eq!(info.client_pin_state(), Some(false), "clientPin unset");
    check_eq!(info.max_msg_size, Some(1200), "maxMsgSize");

    let result = try_ok!(
        client.make_credential(&crate::client::MakeCredentialParams {
            client_data_hash: [0x11; 32],
            rp_id: RP_ID,
            rp_name: Some("NARF Suspend"),
            user_id: &[0x01, 0x02],
            user_name: Some("keys"),
            user_display_name: None,
            exclude: &[],
            resident_key: true,
            user_verification: UserVerification::Discouraged,
            pin: None,
        }),
        "makeCredential over scripted pipe"
    );
    check_eq!(result.fmt, "none", "fmt");
    let attested = try_some!(
        result.auth_data.attested.clone(),
        "attested credential data"
    );
    check_eq!(attested.credential_id, unhex("DEADBEEF"), "credential id");
    check_eq!(attested.aaguid, [0x22; 16], "aaguid");
    check!(result.auth_data.user_present(), "UP flag");
    check!(!result.auth_data.user_verified(), "UV flag clear");

    // ── The client's own frames, byte-for-byte ──
    let written = pipe.written();
    check_eq!(written.len(), 5, "INIT + getInfo + 3-packet makeCredential");

    // Report 0: CTAPHID_INIT on the broadcast channel.
    let mut expect_init = [0u8; REPORT_LEN];
    expect_init[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    expect_init[4] = 0x86;
    expect_init[5..7].copy_from_slice(&8u16.to_be_bytes());
    expect_init[7..15].copy_from_slice(&nonce);
    check_eq!(written[0], expect_init, "INIT frame bytes");

    // Report 1: getInfo = CTAPHID_CBOR [0x04] on the allocated CID.
    let mut expect_info = [0u8; REPORT_LEN];
    expect_info[0..4].copy_from_slice(&0x0A0B0C0Du32.to_be_bytes());
    expect_info[4] = 0x90;
    expect_info[5..7].copy_from_slice(&1u16.to_be_bytes());
    expect_info[7] = 0x04;
    check_eq!(written[1], expect_info, "getInfo frame bytes");

    // Reports 2..: the makeCredential message. Expected CBOR is a
    // hand-built literal from CTAP2 §6.2 + RFC 8949 canonical
    // ordering (note key 4's inner map: "alg" encodes shorter
    // than "type", so alg comes FIRST on the wire).
    let mut expect_msg = unhex("01 A6 01 58 20");
    expect_msg.extend_from_slice(&[0x11; 32]);
    expect_msg.extend_from_slice(&unhex(
        "02 A2 62 6964 6C 73757370656E642E6E617266
            64 6E616D65 6C 4E4152462053757370656E64
         03 A2 62 6964 42 0102
            64 6E616D65 64 6B657973
         04 81 A2 63 616C67 26
                  64 74797065 6A 7075626C69632D6B6579
         06 A1 6B 686D61632D736563726574 F5
         07 A1 62 726B F5",
    ));
    let (msg, consumed) = try_some!(reassemble(&written, 2), "reassemble makeCredential");
    check_eq!(consumed, 3, "makeCredential packet count");
    check_eq!(
        msg,
        expect_msg,
        "makeCredential request must match the spec-shaped frame byte-for-byte"
    );
    check_eq!(
        written[2][0..4],
        0x0A0B0C0Du32.to_be_bytes(),
        "makeCredential CID"
    );
    check_eq!(written[2][4], 0x90, "makeCredential is CTAPHID_CBOR");
    check_eq!(
        u16::from_be_bytes([written[2][5], written[2][6]]) as usize,
        expect_msg.len(),
        "makeCredential BCNT"
    );
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_scripted_make_credential_frame_is_byte_exact);

// ── (b) hmac-secret derivation cross-checked independently ─────

fn smoke_derive_matches_independent_hmac_computation() -> TestResult {
    let (mut client, token) = try_ok!(fixture_client(0xA1), "connect");
    // PIN state starts unset, visible in getInfo.
    check_eq!(
        try_ok!(client.get_info(), "getInfo").client_pin_state(),
        Some(false),
        "clientPin starts unset"
    );
    let enrolled = try_ok!(enroll_pin(&mut client, PIN), "enroll with PIN");
    // Enrollment configured the PIN and refreshed its view.
    check_eq!(
        try_ok!(client.get_info(), "getInfo after enroll").client_pin_state(),
        Some(true),
        "clientPin set after enroll"
    );
    // The credential creation genuinely waited for a touch.
    check!(
        client.channel().last_keepalive_up_needed() >= 1,
        "makeCredential waited for UP (keepalives seen)"
    );

    let cred_random = try_some!(
        token.borrow().cred_random(&enrolled.credential_id),
        "fixture knows the credential"
    );

    let salt1 = [0x51; 32];
    let out = try_ok!(
        derive(&mut client, &enrolled.credential_id, salt1, None, Some(PIN)),
        "derive one salt"
    );
    // Independent computation: CTAP2 §6.4 output is
    // HMAC-SHA-256(credRandom, salt) — computed here directly
    // from the fixture's stored secret via narf-crypto's HKDF
    // module, sharing no code with either the client's or the
    // fixture-token's assertion path.
    check_eq!(
        out.first,
        lib_hmac_sha256(&cred_random, &salt1),
        "output == HMAC(credRandom, salt1)"
    );
    check_eq!(out.second, None, "single salt gives single output");

    // Two salts → two independent outputs in one call.
    let salt2 = [0x52; 32];
    let out2 = try_ok!(
        derive(
            &mut client,
            &enrolled.credential_id,
            salt1,
            Some(salt2),
            Some(PIN)
        ),
        "derive two salts"
    );
    check_eq!(
        out2.first,
        lib_hmac_sha256(&cred_random, &salt1),
        "two-salt first output"
    );
    check_eq!(
        out2.second,
        Some(lib_hmac_sha256(&cred_random, &salt2)),
        "two-salt second output"
    );
    check!(
        out2.first != out2.second.unwrap_or([0; 32]),
        "salt outputs differ"
    );
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_derive_matches_independent_hmac_computation);

// ── (c) PIN failures ───────────────────────────────────────────

fn smoke_wrong_pin_counts_retries_and_blocks() -> TestResult {
    let (mut client, token) = try_ok!(fixture_client(0xB2), "connect");
    let enrolled = try_ok!(enroll_pin(&mut client, PIN), "enroll");
    check_eq!(
        try_ok!(client.pin_retries(), "retries"),
        8,
        "fresh retry budget"
    );

    // Wrong PIN → CTAP2_ERR_PIN_INVALID, counter decrements.
    let err = try_err!(
        derive(
            &mut client,
            &enrolled.credential_id,
            [1; 32],
            None,
            Some(b"9999")
        ),
        "wrong PIN must fail"
    );
    check_eq!(
        err,
        Error::Ctap(status::CTAP2_ERR_PIN_INVALID),
        "wrong PIN status"
    );
    check!(err.is_pin_invalid(), "is_pin_invalid helper");
    check_eq!(
        try_ok!(client.pin_retries(), "retries after wrong"),
        7,
        "counter decremented"
    );
    check_eq!(token.borrow().pin_retries(), 7, "fixture counter agrees");

    // Correct PIN still works and resets the counter.
    try_ok!(
        derive(
            &mut client,
            &enrolled.credential_id,
            [1; 32],
            None,
            Some(PIN)
        ),
        "correct PIN"
    );
    check_eq!(
        try_ok!(client.pin_retries(), "retries after success"),
        8,
        "counter reset"
    );

    // Exhaust the counter: attempts 1..=7 report PIN_INVALID…
    for _ in 0..7 {
        let err = try_err!(
            derive(
                &mut client,
                &enrolled.credential_id,
                [1; 32],
                None,
                Some(b"9999")
            ),
            "wrong PIN must fail"
        );
        check_eq!(
            err,
            Error::Ctap(status::CTAP2_ERR_PIN_INVALID),
            "pre-block attempts"
        );
    }
    check_eq!(
        try_ok!(client.pin_retries(), "retries at 1"),
        1,
        "one retry left"
    );
    // …the 8th wrong attempt blocks the PIN…
    let err = try_err!(
        derive(
            &mut client,
            &enrolled.credential_id,
            [1; 32],
            None,
            Some(b"9999")
        ),
        "exhausting attempt must fail"
    );
    check_eq!(
        err,
        Error::Ctap(status::CTAP2_ERR_PIN_BLOCKED),
        "blocked at exhaustion"
    );
    // …and even the correct PIN is refused until a power cycle.
    let err = try_err!(
        derive(
            &mut client,
            &enrolled.credential_id,
            [1; 32],
            None,
            Some(PIN)
        ),
        "blocked PIN refuses even the right PIN"
    );
    check_eq!(
        err,
        Error::Ctap(status::CTAP2_ERR_PIN_BLOCKED),
        "still blocked"
    );
    token.borrow_mut().power_cycle();
    try_ok!(
        derive(
            &mut client,
            &enrolled.credential_id,
            [1; 32],
            None,
            Some(PIN)
        ),
        "power cycle restores PIN use"
    );
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_wrong_pin_counts_retries_and_blocks);

fn smoke_bad_pin_uv_auth_param_refused() -> TestResult {
    let (mut client, _token) = try_ok!(fixture_client(0xC3), "connect");
    let enrolled = try_ok!(enroll_pin(&mut client, PIN), "enroll");

    // Obtain a genuine pinUvAuthToken, then present a corrupted
    // pinUvAuthParam in a hand-built getAssertion: the fixture
    // must refuse with CTAP2_ERR_PIN_AUTH_INVALID (spec §6.3) —
    // a *proof* failure, distinct from a wrong PIN.
    let session = try_ok!(client.pin_session(), "pin session");
    let _token_bytes = try_ok!(
        session.get_pin_token(client.channel(), PIN),
        "genuine PIN token fetch"
    );
    let descriptor = Value::Map(alloc::vec![
        (
            Value::text("id"),
            Value::Bytes(enrolled.credential_id.clone())
        ),
        (Value::text("type"), Value::text("public-key")),
    ]);
    let req = Value::Map(alloc::vec![
        (Value::int(1), Value::text(RP_ID)),
        (Value::int(2), Value::Bytes(CDH.to_vec())),
        (Value::int(3), Value::Array(alloc::vec![descriptor])),
        (Value::int(6), Value::Bytes(alloc::vec![0xAA; 16])),
        (Value::int(7), Value::uint(1)),
    ]);
    let mut bytes = alloc::vec![crate::client::CMD_GET_ASSERTION];
    bytes.extend_from_slice(&crate::cbor::encode(&req));
    let err = try_err!(
        client.channel().exchange_cbor(&bytes),
        "corrupt pinUvAuthParam must be refused"
    );
    check_eq!(
        err,
        Error::Ctap(status::CTAP2_ERR_PIN_AUTH_INVALID),
        "proof failure status"
    );
    check!(err.is_pin_auth_invalid(), "is_pin_auth_invalid helper");
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_bad_pin_uv_auth_param_refused);

// ── (d) multi-credential responses ─────────────────────────────

fn smoke_multi_credential_next_assertion() -> TestResult {
    let (mut client, _token) = try_ok!(fixture_client(0xD4), "connect");
    // Two discoverable credentials for the same RP on one token.
    let mut enrolled_ids = Vec::new();
    for _ in 0..2 {
        let e = try_ok!(
            enroll_token(
                &mut client,
                &EnrollParams {
                    client_data_hash: CDH,
                    rp_id: RP_ID,
                    rp_name: None,
                    user_id: &[9, 9],
                    user_name: None,
                    pin_setup: PinSetup::TouchOnly,
                },
            ),
            "touch-only enroll"
        );
        enrolled_ids.push(e.credential_id);
    }
    check!(
        enrolled_ids[0] != enrolled_ids[1],
        "distinct credential ids"
    );

    // Discoverable lookup: first assertion reports the total.
    let first = try_ok!(
        client.get_assertion(&GetAssertionParams {
            rp_id: RP_ID,
            client_data_hash: CDH,
            allow: &[],
            user_verification: UserVerification::Discouraged,
            hmac_secret: None,
            pin: None,
        }),
        "first assertion"
    );
    check_eq!(first.number_of_credentials, Some(2), "total reported");
    let first_id = try_some!(first.credential.as_ref(), "first credential")
        .id
        .clone();
    check!(
        enrolled_ids.contains(&first_id),
        "first id is an enrolled one"
    );
    check_eq!(first.auth_data.sign_count, 1, "first sign count");

    // getNextAssertion serves the other credential.
    let second = try_ok!(client.get_next_assertion(RP_ID), "next assertion");
    let second_id = try_some!(second.credential.as_ref(), "second credential")
        .id
        .clone();
    check!(
        first_id != second_id,
        "next assertion is the other credential"
    );
    check!(
        enrolled_ids.contains(&second_id),
        "second id is an enrolled one"
    );
    check_eq!(second.number_of_credentials, None, "total only on first");
    check_eq!(second.auth_data.sign_count, 1, "second sign count");

    // Queue drained → CTAP2_ERR_NO_OPERATIONS.
    let err = try_err!(client.get_next_assertion(RP_ID), "queue must be drained");
    check_eq!(
        err,
        Error::Ctap(status::CTAP2_ERR_NO_OPERATIONS),
        "drained status"
    );
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_multi_credential_next_assertion);

// ── (e) malformed inputs ───────────────────────────────────────

struct ZeroPipe;
impl HidPipe for ZeroPipe {
    fn write_report(&mut self, _report: &[u8; REPORT_LEN]) -> Result<(), Error> {
        Ok(())
    }
    fn read_report(&mut self, out: &mut [u8; REPORT_LEN]) -> Result<(), Error> {
        *out = [0u8; REPORT_LEN];
        Ok(())
    }
}

fn smoke_malformed_inputs_are_clean_errors() -> TestResult {
    // Corrupted CBOR from the token → decode error, no panic.
    let token = Rc::new(RefCell::new(FixtureToken::new([0xE5; 32])));
    token.borrow_mut().corrupt_next_cbor_response();
    let pipe = FixturePipe::new(token.clone());
    let err = try_err!(
        Client::connect(pipe, FixtureRng::new([1; 32])),
        "corrupt getInfo must fail the connect"
    );
    check!(matches!(err, Error::Cbor(_)), "expected CBOR error");

    // Traffic on an unallocated CID → CTAPHID ERROR frame
    // INVALID_CHANNEL (0x0B) surfaced as Error::Hid.
    let token2 = Rc::new(RefCell::new(FixtureToken::new([0xE6; 32])));
    let pipe2 = FixturePipe::new(token2);
    let mut channel = Channel::from_parts(pipe2, 0xDEAD_BEEF);
    let err = try_err!(
        channel.exchange_cbor(&[crate::client::CMD_GET_INFO]),
        "unknown channel must error"
    );
    check_eq!(
        err,
        Error::Hid(crate::ctaphid::ERR_INVALID_CHANNEL),
        "invalid channel"
    );

    // A pipe of zeros → no INIT response ever assembles → the
    // exchange budget expires with a Timeout (no panic, no hang).
    let err = try_err!(
        Channel::init(ZeroPipe, &mut FixtureRng::new([2; 32])),
        "zero pipe cannot initialize"
    );
    check_eq!(err, Error::Timeout, "zero pipe times out");

    // INIT response with a wrong nonce echo → Protocol error.
    let pipe = ScriptedPipe::default();
    let mut bad_init = alloc::vec![0u8; 8]; // wrong nonce
    bad_init.extend_from_slice(&unhex("0A0B0C0D 02 01 00 00 02"));
    pipe.push_response(0xFFFF_FFFF, 0x06, &bad_init);
    let err = try_err!(
        Channel::init(pipe, &mut FixtureRng::new([7u8; 32])),
        "nonce mismatch must fail"
    );
    check!(matches!(err, Error::Protocol(_)), "nonce error kind");

    // INIT response with a short payload (BCNT 5, not 17).
    let pipe = ScriptedPipe::default();
    pipe.push_response(0xFFFF_FFFF, 0x06, &[1, 2, 3, 4, 5]);
    let err = try_err!(
        Channel::init(pipe, &mut FixtureRng::new([7u8; 32])),
        "short INIT must fail"
    );
    check!(matches!(err, Error::Protocol(_)), "short INIT error kind");
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_malformed_inputs_are_clean_errors);

// ── (f) backup token: distinct credential + distinct output ────

fn smoke_backup_token_distinct_credential_and_output() -> TestResult {
    let salt = [0x77; 32];
    let (mut client_a, token_a) = try_ok!(fixture_client(0xF1), "connect primary");
    let primary = try_ok!(enroll_pin(&mut client_a, PIN), "enroll primary");
    // One token is NOT a complete enrollment (mandatory backup).
    check!(
        !enrollment_complete(core::slice::from_ref(&primary)),
        "single token is incomplete"
    );

    let (mut client_b, token_b) = try_ok!(fixture_client(0xF2), "connect backup");
    let backup = try_ok!(enroll_pin(&mut client_b, PIN), "enroll backup");
    // Duplicates of one credential do not complete it either.
    check!(
        !enrollment_complete(&[primary.clone(), primary.clone()]),
        "duplicated credential is incomplete"
    );
    check!(
        enrollment_complete(&[primary.clone(), backup.clone()]),
        "two distinct tokens complete enrollment"
    );
    check!(
        primary.credential_id != backup.credential_id,
        "distinct credential ids"
    );

    // Same salt, same PIN — DIFFERENT outputs, because each token
    // wraps with its own per-credential secret. Recovery works
    // per-token: P1 stores one wrapped blob per enrolled token.
    let out_a = try_ok!(
        derive(&mut client_a, &primary.credential_id, salt, None, Some(PIN)),
        "derive primary"
    );
    let out_b = try_ok!(
        derive(&mut client_b, &backup.credential_id, salt, None, Some(PIN)),
        "derive backup"
    );
    check!(out_a.first != out_b.first, "outputs differ across tokens");
    let secret_a = try_some!(
        token_a.borrow().cred_random(&primary.credential_id),
        "primary secret"
    );
    let secret_b = try_some!(
        token_b.borrow().cred_random(&backup.credential_id),
        "backup secret"
    );
    check_eq!(
        out_a.first,
        lib_hmac_sha256(&secret_a, &salt),
        "primary output cross-check"
    );
    check_eq!(
        out_b.first,
        lib_hmac_sha256(&secret_b, &salt),
        "backup output cross-check"
    );
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_backup_token_distinct_credential_and_output);

// ── structural user presence ────────────────────────────────────

fn smoke_no_touch_no_credential() -> TestResult {
    // Manual-touch fixture (no auto-touch): a makeCredential the
    // user never confirms can never complete — the client's
    // exchange budget expires instead.
    let token = Rc::new(RefCell::new(FixtureToken::new([0x99; 32])));
    let pipe = FixturePipe::new(token.clone());
    let mut client = try_ok!(Client::connect(pipe, FixtureRng::new([3; 32])), "connect");
    let params = crate::client::MakeCredentialParams {
        client_data_hash: CDH,
        rp_id: RP_ID,
        rp_name: None,
        user_id: &[1],
        user_name: None,
        user_display_name: None,
        exclude: &[],
        resident_key: true,
        user_verification: UserVerification::Discouraged,
        pin: None,
    };
    let err = try_err!(
        client.make_credential(&params),
        "untouched op must not complete"
    );
    check_eq!(err, Error::Timeout, "untouched op times out");
    check!(
        client.channel().last_keepalive_up_needed() > 0,
        "token must have asked for UP"
    );
    check_eq!(
        token.borrow().credential_count(),
        0,
        "no credential without touch"
    );
    // After a touch, the same call succeeds.
    token.borrow_mut().touch();
    try_ok!(client.make_credential(&params), "touched op completes");
    check_eq!(
        token.borrow().credential_count(),
        1,
        "credential created after touch"
    );
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_no_touch_no_credential);

// ── enrollment honesty knobs ────────────────────────────────────

fn smoke_enrollment_rejects_token_without_hmac_grant() -> TestResult {
    // Token advertises the extension but does not grant it in the
    // credential's authData → enrollment must fail, not downgrade.
    let (mut client, token) = try_ok!(fixture_client(0x77), "connect");
    token.borrow_mut().set_grant_hmac(false);
    let err = try_err!(
        enroll_token(
            &mut client,
            &EnrollParams {
                client_data_hash: CDH,
                rp_id: RP_ID,
                rp_name: None,
                user_id: &[1],
                user_name: None,
                pin_setup: PinSetup::TouchOnly,
            },
        ),
        "ungranted hmac-secret must fail enrollment"
    );
    check!(matches!(err, Error::Unsupported(_)), "ungranted error kind");

    // Token that doesn't even advertise hmac-secret → also
    // refused. The knob is set BEFORE connect: the client caches
    // getInfo, so the short list must be advertised from the start.
    let token2 = Rc::new(RefCell::new(FixtureToken::new([0x78; 32])));
    token2.borrow_mut().set_auto_touch(2);
    token2
        .borrow_mut()
        .set_advertised_extensions(alloc::vec!["credProtect".into()]);
    let pipe2 = FixturePipe::new(token2.clone());
    let mut client2 = try_ok!(
        Client::connect(pipe2, FixtureRng::new([0xC1; 32])),
        "connect 2"
    );
    let err = try_err!(
        enroll_token(
            &mut client2,
            &EnrollParams {
                client_data_hash: CDH,
                rp_id: RP_ID,
                rp_name: None,
                user_id: &[1],
                user_name: None,
                pin_setup: PinSetup::TouchOnly,
            },
        ),
        "unadvertised hmac-secret must fail enrollment"
    );
    check!(
        matches!(err, Error::Unsupported(_)),
        "unadvertised error kind"
    );
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_enrollment_rejects_token_without_hmac_grant);

// ── PIN lifecycle ───────────────────────────────────────────────

fn smoke_change_pin_flow() -> TestResult {
    let (mut client, _token) = try_ok!(fixture_client(0x55), "connect");
    let enrolled = try_ok!(enroll_pin(&mut client, PIN), "enroll");
    let session = try_ok!(client.pin_session(), "pin session");
    // Too-short PINs are refused client-side before any traffic.
    check!(
        matches!(
            session.set_pin(client.channel(), b"12"),
            Err(Error::Protocol(_))
        ),
        "short PIN refused client-side"
    );
    try_ok!(
        session.change_pin(client.channel(), PIN, b"5678"),
        "changePIN with correct current PIN"
    );
    let err = try_err!(
        derive(
            &mut client,
            &enrolled.credential_id,
            [4; 32],
            None,
            Some(PIN)
        ),
        "old PIN must stop working"
    );
    check_eq!(
        err,
        Error::Ctap(status::CTAP2_ERR_PIN_INVALID),
        "old PIN invalid"
    );
    try_ok!(
        derive(
            &mut client,
            &enrolled.credential_id,
            [4; 32],
            None,
            Some(b"5678")
        ),
        "new PIN works"
    );
    TestResult::Pass
}
kernel_test_in!("ctap2", smoke_change_pin_flow);
