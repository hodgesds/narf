//! A fixture FIDO2 authenticator, written **independently** of
//! the client in this crate: its own hand-rolled CBOR, its own
//! AES-CBC, HMAC via `narf-crypto`'s HKDF module (a different code
//! path from the client's [`crate::crypto`]), and hmac-secret
//! outputs computed as `HMAC-SHA-256(credRandom, salt)` straight
//! from the CTAP2 §6.4 definition. If client and fixture agree on
//! a wrong constant or framing, they would have had to make the
//! same mistake from the spec text twice, in different code.
//!
//! Modelled behaviour (all from the spec text):
//!
//! - CTAPHID INIT/channel allocation, PING echo, CBOR channel,
//!   ERROR frames for unknown channels.
//! - getInfo with versions/extensions/aaguid/options(clientPin
//!   reflects PIN state)/pinUvAuthProtocols [1].
//! - clientPIN protocol one: getKeyAgreement (one ephemeral per
//!   power cycle), getPINRetries, setPIN, changePIN (full-length
//!   HMAC over newPinEnc), getPINToken with retry counting —
//!   wrong PIN → CTAP2_ERR_PIN_INVALID and the counter
//!   decrements; exhausted → CTAP2_ERR_PIN_BLOCKED until
//!   [`FixtureToken::power_cycle`].
//! - makeCredential: ES256-only, exclude-list, uv via
//!   pinUvAuthParam verification (bad proof →
//!   CTAP2_ERR_PIN_AUTH_INVALID), attested authData with the
//!   hmac-secret grant reflected in the ED extensions.
//! - getAssertion: allow-list + discoverable matching,
//!   numberOfCredentials + a real getNextAssertion queue,
//!   per-credential counters, ECDSA signatures over
//!   authData‖clientDataHash, hmac-secret with saltAuth
//!   verification and salt/output encryption under the key
//!   agreement.
//! - **User presence is structural, not a flag**: an operation
//!   that needs UP parks in `pending`; polls return KEEPALIVE
//!   UP_NEEDED; only [`FixtureToken::touch`] completes it. A
//!   client that never waits for the touch never gets a result.
//!
//! Determinism: every random draw (ephemerals, credential ids and
//! secrets, PIN tokens) comes from a seeded SHA-256 counter
//! chain, so fixtures are reproducible byte-for-byte.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_crypto::hkdf::hmac_sha256 as lib_hmac_sha256;
use narf_crypto::p256::ecdsa::sign_p256;
use narf_crypto::p256::point::{scalar_mul, scalar_mul_base};
use narf_crypto::p256::{AffinePoint, Scalar};
use narf_crypto::sha256::Sha256;

use crate::ctaphid::{HidPipe, REPORT_LEN};
use crate::{Error, RandomSource};

/// Fixture AAGUID: ASCII "narf-fixture" + zero padding.
pub const FIXTURE_AAGUID: [u8; 16] = *b"narf-fixture\0\0\0\0";
const MAX_PIN_RETRIES: u8 = 8;

// ── Deterministic RNG (SHA-256(seed ‖ counter) chain) ──────────

/// A reproducible byte source for fixtures on both sides of the
/// pipe: the token's internals and the client's ephemerals.
pub struct FixtureRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl FixtureRng {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0u8; 32],
            used: 32,
        }
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            if self.used >= 32 {
                let mut h = Sha256::new();
                h.update(&self.seed);
                h.update(&self.counter.to_be_bytes());
                self.block = h.finalize();
                self.counter += 1;
                self.used = 0;
            }
            *b = self.block[self.used];
            self.used += 1;
        }
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }

    fn scalar(&mut self) -> Scalar {
        loop {
            let b = self.bytes::<32>();
            let s = Scalar::from_bytes_be_reduce(&b);
            if !s.is_zero() {
                return s;
            }
        }
    }
}

impl RandomSource for FixtureRng {
    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.fill(out);
        Ok(())
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

fn sha256_two(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize()
}

// ── Fixture-side CBOR (own implementation, not the client's) ────

#[derive(Clone, Debug, PartialEq)]
enum FVal {
    UInt(u64),
    NInt(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<FVal>),
    Map(Vec<(FVal, FVal)>),
    Bool(bool),
}

impl FVal {
    fn get_int(&self, key: i64) -> Option<&FVal> {
        if let FVal::Map(entries) = self {
            let want = if key >= 0 {
                FVal::UInt(key as u64)
            } else {
                FVal::NInt(key)
            };
            entries.iter().find(|(k, _)| *k == want).map(|(_, v)| v)
        } else {
            None
        }
    }
    fn get_text(&self, key: &str) -> Option<&FVal> {
        if let FVal::Map(entries) = self {
            entries
                .iter()
                .find(|(k, _)| matches!(k, FVal::Text(t) if t == key))
                .map(|(_, v)| v)
        } else {
            None
        }
    }
    fn as_bytes(&self) -> Option<&[u8]> {
        if let FVal::Bytes(b) = self {
            Some(b)
        } else {
            None
        }
    }
    fn as_text(&self) -> Option<&str> {
        if let FVal::Text(t) = self {
            Some(t)
        } else {
            None
        }
    }
    fn as_uint(&self) -> Option<u64> {
        if let FVal::UInt(n) = self {
            Some(*n)
        } else {
            None
        }
    }
    fn as_bool(&self) -> Option<bool> {
        if let FVal::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
}

fn fenc_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg <= 0xFF {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= 0xFFFF {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xFFFF_FFFF {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn fenc(v: &FVal, out: &mut Vec<u8>) {
    match v {
        FVal::UInt(n) => fenc_head(0, *n, out),
        FVal::NInt(n) => fenc_head(1, (-1 - n) as u64, out),
        FVal::Bytes(b) => {
            fenc_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        FVal::Text(t) => {
            fenc_head(3, t.len() as u64, out);
            out.extend_from_slice(t.as_bytes());
        }
        FVal::Array(items) => {
            fenc_head(4, items.len() as u64, out);
            for i in items {
                fenc(i, out);
            }
        }
        FVal::Map(entries) => {
            // Canonical: sort by encoded key (length, then bytes).
            let mut keyed: Vec<(Vec<u8>, &FVal)> = entries
                .iter()
                .map(|(k, val)| {
                    let mut kb = Vec::new();
                    fenc(k, &mut kb);
                    (kb, val)
                })
                .collect();
            keyed.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
            fenc_head(5, keyed.len() as u64, out);
            for (kb, val) in keyed {
                out.extend_from_slice(&kb);
                fenc(val, out);
            }
        }
        FVal::Bool(b) => out.push(if *b { 0xF5 } else { 0xF4 }),
    }
}

fn fencode(v: &FVal) -> Vec<u8> {
    let mut out = Vec::new();
    fenc(v, &mut out);
    out
}

fn fdec(data: &[u8]) -> Option<(FVal, usize)> {
    fn arg(data: &[u8], addl: u8) -> Option<(u64, usize)> {
        match addl {
            0..=23 => Some((addl as u64, 1)),
            24 => Some((data.get(1).copied()? as u64, 2)),
            25 => Some((u16::from_be_bytes([*data.get(1)?, *data.get(2)?]) as u64, 3)),
            26 => Some((
                u32::from_be_bytes([*data.get(1)?, *data.get(2)?, *data.get(3)?, *data.get(4)?])
                    as u64,
                5,
            )),
            27 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(data.get(1..9)?);
                Some((u64::from_be_bytes(b), 9))
            }
            _ => None,
        }
    }
    fn rec(data: &[u8], depth: usize) -> Option<(FVal, usize)> {
        if depth > 12 || data.is_empty() {
            return None;
        }
        let major = data[0] >> 5;
        let addl = data[0] & 0x1F;
        match major {
            0 | 1 => {
                let (a, n) = arg(data, addl)?;
                if major == 0 {
                    Some((FVal::UInt(a), n))
                } else {
                    Some((FVal::NInt(-1 - a as i64), n))
                }
            }
            2 | 3 => {
                let (len, n) = arg(data, addl)?;
                let len = len as usize;
                let s = data.get(n..n + len)?;
                if major == 2 {
                    Some((FVal::Bytes(s.to_vec()), n + len))
                } else {
                    Some((FVal::Text(String::from_utf8(s.to_vec()).ok()?), n + len))
                }
            }
            4 => {
                let (count, mut n) = arg(data, addl)?;
                let mut items = Vec::new();
                for _ in 0..count {
                    let (v, used) = rec(&data[n..], depth + 1)?;
                    n += used;
                    items.push(v);
                }
                Some((FVal::Array(items), n))
            }
            5 => {
                let (count, mut n) = arg(data, addl)?;
                let mut entries = Vec::new();
                for _ in 0..count {
                    let (k, used) = rec(&data[n..], depth + 1)?;
                    n += used;
                    let (v, used) = rec(&data[n..], depth + 1)?;
                    n += used;
                    entries.push((k, v));
                }
                Some((FVal::Map(entries), n))
            }
            7 => match addl {
                20 => Some((FVal::Bool(false), 1)),
                21 => Some((FVal::Bool(true), 1)),
                _ => None,
            },
            _ => None,
        }
    }
    rec(data, 0)
}

// ── Fixture-side AES-256-CBC (own loop over the aes block cipher) ─

fn fixture_aes_cbc(key: &[u8; 32], data: &[u8], encrypt: bool) -> Option<Vec<u8>> {
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use aes::Aes256;
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return None;
    }
    let cipher = Aes256::new(key.into());
    let mut out = Vec::with_capacity(data.len());
    let mut prev = [0u8; 16];
    for chunk in data.chunks_exact(16) {
        let mut block = *aes::cipher::generic_array::GenericArray::from_slice(chunk);
        if encrypt {
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
            prev.copy_from_slice(&block);
        } else {
            let cipher_block: [u8; 16] = block.into();
            cipher.decrypt_block(&mut block);
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            out.extend_from_slice(&block);
            prev = cipher_block;
        }
    }
    Some(out)
}

fn fixture_ecdh_shared(secret: &Scalar, peer_xy: &[u8]) -> Option<[u8; 32]> {
    let peer = AffinePoint::from_encoded(peer_xy)?;
    let shared = scalar_mul(secret, &peer);
    let enc = shared.to_encoded()?;
    Some(sha256(&enc[..32]))
}

fn fixture_cose_parse(v: &FVal) -> Option<[u8; 64]> {
    let x = v.get_int(-2)?.as_bytes()?;
    let y = v.get_int(-3)?.as_bytes()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(x);
    out[32..].copy_from_slice(y);
    Some(out)
}

fn fixture_cose_key(public_xy: &[u8; 64], alg: i64) -> FVal {
    FVal::Map(alloc::vec![
        (FVal::UInt(1), FVal::UInt(2)),
        (FVal::UInt(3), FVal::NInt(alg)),
        (FVal::NInt(-1), FVal::UInt(1)),
        (FVal::NInt(-2), FVal::Bytes(public_xy[..32].to_vec())),
        (FVal::NInt(-3), FVal::Bytes(public_xy[32..].to_vec())),
    ])
}

// ── Token state ─────────────────────────────────────────────────

struct FixtureCred {
    id: Vec<u8>,
    rp_id: String,
    user_id: Vec<u8>,
    user_name: Option<String>,
    /// Per-credential signing scalar (bytes, for sign_p256).
    signing_key: [u8; 32],
    /// The hmac-secret per-credential secret ("credRandom").
    cred_random: [u8; 32],
    hmac_secret_enabled: bool,
    resident: bool,
    sign_count: u32,
}

enum Pending {
    MakeCredential(Box<MakeWork>),
    GetAssertion(Box<AssertWork>),
}

struct MakeWork {
    rp_id: String,
    user_id: Vec<u8>,
    user_name: Option<String>,
    exclude: Vec<Vec<u8>>,
    want_hmac: bool,
    resident: bool,
    uv_verified: bool,
}

struct AssertWork {
    cred_idx: usize,
    client_data_hash: [u8; 32],
    uv_verified: bool,
    /// (salts, shared secret) when hmac-secret was requested.
    hmac: Option<(Vec<u8>, [u8; 32])>,
    /// Total matches for numberOfCredentials (first response).
    total_matches: usize,
    /// Remaining (cred_idx) to serve via getNextAssertion, with
    /// the clientDataHash they must be signed against.
    rest: Vec<(usize, [u8; 32], bool)>,
}

/// The fixture authenticator. Drive it through [`FixturePipe`];
/// call [`FixtureToken::touch`] to release parked operations.
pub struct FixtureToken {
    rng: FixtureRng,
    allocated_cid: Option<u32>,
    next_cid: u32,
    // Reassembly
    rx_cmd: u8,
    rx_buf: Vec<u8>,
    rx_want: usize,
    rx_seq: u8,
    rx_open: bool,
    out_queue: VecDeque<[u8; REPORT_LEN]>,
    // PIN / key agreement
    pin: Option<Vec<u8>>,
    pin_retries: u8,
    pin_token: Option<[u8; 32]>,
    ka_secret: Scalar,
    ka_public: [u8; 64],
    creds: Vec<FixtureCred>,
    pending: Option<Pending>,
    touched: bool,
    /// Test knob: when `Some(n)`, a parked operation completes
    /// after `n` UP_NEEDED keepalives have been emitted (the
    /// synchronous client cannot touch mid-call). `None` (the
    /// default) means only an explicit [`FixtureToken::touch`]
    /// releases parked work — the structural no-touch property.
    auto_touch_after: Option<usize>,
    keepalives_sent: usize,
    assertion_rest: Vec<(usize, [u8; 32], bool)>,
    // Behaviour knobs (tests)
    grant_hmac: bool,
    corrupt_next_cbor: bool,
    advertised_extensions: Vec<String>,
}

impl FixtureToken {
    pub fn new(seed: [u8; 32]) -> Self {
        let mut rng = FixtureRng::new(seed);
        let ka_secret = rng.scalar();
        let ka_public = scalar_mul_base(&ka_secret)
            .to_encoded()
            .expect("generator mul");
        Self {
            rng,
            allocated_cid: None,
            next_cid: 0x1000_0001,
            rx_cmd: 0,
            rx_buf: Vec::new(),
            rx_want: 0,
            rx_seq: 0,
            rx_open: false,
            out_queue: VecDeque::new(),
            pin: None,
            pin_retries: MAX_PIN_RETRIES,
            pin_token: None,
            ka_secret,
            ka_public,
            creds: Vec::new(),
            pending: None,
            touched: false,
            auto_touch_after: None,
            keepalives_sent: 0,
            assertion_rest: Vec::new(),
            grant_hmac: true,
            corrupt_next_cbor: false,
            advertised_extensions: alloc::vec!["hmac-secret".into(), "credProtect".into()],
        }
    }

    /// Simulate the user touching the token: parked operations
    /// complete on the next poll.
    pub fn touch(&mut self) {
        self.touched = true;
    }

    /// Test knob: release parked operations after `n` UP_NEEDED
    /// keepalives (see the field docs). Manual-touch mode is the
    /// default; flow tests opt into this.
    pub fn set_auto_touch(&mut self, after_keepalives: usize) {
        self.auto_touch_after = Some(after_keepalives);
    }

    /// Power cycle: PIN retries restore, pinUvAuthToken and the
    /// key-agreement ephemeral are invalidated, parked work dies.
    pub fn power_cycle(&mut self) {
        self.pin_retries = MAX_PIN_RETRIES;
        self.pin_token = None;
        self.ka_secret = self.rng.scalar();
        self.ka_public = scalar_mul_base(&self.ka_secret)
            .to_encoded()
            .expect("generator mul");
        self.pending = None;
        self.assertion_rest.clear();
    }

    pub fn pin_retries(&self) -> u8 {
        self.pin_retries
    }

    pub fn credential_count(&self) -> usize {
        self.creds.len()
    }

    /// Test accessor: the per-credential hmac secret, so tests
    /// can compute the expected output independently of both the
    /// client and the fixture's own assertion path.
    pub fn cred_random(&self, credential_id: &[u8]) -> Option<[u8; 32]> {
        self.creds
            .iter()
            .find(|c| c.id == credential_id)
            .map(|c| c.cred_random)
    }

    /// Knob: make makeCredential silently NOT grant hmac-secret
    /// (enrollment must reject the token).
    pub fn set_grant_hmac(&mut self, grant: bool) {
        self.grant_hmac = grant;
    }

    /// Knob: advertise a different extension list in getInfo.
    pub fn set_advertised_extensions(&mut self, exts: Vec<String>) {
        self.advertised_extensions = exts;
    }

    /// Knob: corrupt the next CBOR response payload (byte flip)
    /// so the client must surface a clean decode error.
    pub fn corrupt_next_cbor_response(&mut self) {
        self.corrupt_next_cbor = true;
    }

    // ── report plumbing ─────────────────────────────────────────

    fn queue_message(&mut self, cid: u32, cmd: u8, payload: &[u8]) {
        let mut first = [0u8; REPORT_LEN];
        first[0..4].copy_from_slice(&cid.to_be_bytes());
        first[4] = 0x80 | cmd;
        first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let n = core::cmp::min(payload.len(), 57);
        first[7..7 + n].copy_from_slice(&payload[..n]);
        self.out_queue.push_back(first);
        let mut rest = &payload[n..];
        let mut seq = 0u8;
        while !rest.is_empty() {
            let mut r = [0u8; REPORT_LEN];
            r[0..4].copy_from_slice(&cid.to_be_bytes());
            r[4] = seq;
            seq = seq.wrapping_add(1);
            let n = core::cmp::min(rest.len(), 59);
            r[5..5 + n].copy_from_slice(&rest[..n]);
            self.out_queue.push_back(r);
            rest = &rest[n..];
        }
    }

    fn queue_error(&mut self, cid: u32, code: u8) {
        self.queue_message(cid, 0x3F, &[code]);
    }

    fn queue_status(&mut self, cid: u32, status: u8) {
        let payload = [status];
        self.queue_cbor_payload(cid, &payload);
    }

    fn queue_cbor_payload(&mut self, cid: u32, payload: &[u8]) {
        let mut payload = payload.to_vec();
        if self.corrupt_next_cbor && payload.len() > 2 {
            self.corrupt_next_cbor = false;
            let i = payload.len() - 1;
            payload[i] ^= 0xFF;
        }
        self.queue_message(cid, 0x10, &payload);
    }

    fn queue_cbor_ok(&mut self, cid: u32, body: &FVal) {
        let mut payload = alloc::vec![0x00];
        payload.extend_from_slice(&fencode(body));
        self.queue_cbor_payload(cid, &payload);
    }

    /// Feed one client report into the token. Public so
    /// downstream harnesses whose pipe must be `Send` (e.g. the
    /// power resume fixtures, whose custody trait demands
    /// `Send + Sync`) can drive the token through their own
    /// [`HidPipe`] impl instead of the `Rc`-based [`FixturePipe`].
    pub fn handle_report(&mut self, report: &[u8; REPORT_LEN]) {
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        let is_init = report[4] & 0x80 != 0;
        if is_init {
            let cmd = report[4] & 0x7F;
            let bcnt = u16::from_be_bytes([report[5], report[6]]) as usize;
            self.rx_cmd = cmd;
            self.rx_buf.clear();
            self.rx_want = bcnt;
            self.rx_seq = 0;
            self.rx_open = true;
            let take = core::cmp::min(bcnt, 57);
            self.rx_buf.extend_from_slice(&report[7..7 + take]);
            let _ = cid;
            if self.rx_buf.len() >= self.rx_want {
                self.rx_open = false;
                let payload = core::mem::take(&mut self.rx_buf);
                self.dispatch(cid, cmd, &payload);
            }
        } else if self.rx_open {
            if report[4] != self.rx_seq {
                self.rx_open = false;
                self.queue_error(cid, 0x04); // INVALID_SEQ
                return;
            }
            self.rx_seq = self.rx_seq.wrapping_add(1);
            let need = self.rx_want - self.rx_buf.len();
            let take = core::cmp::min(need, 59);
            self.rx_buf.extend_from_slice(&report[5..5 + take]);
            if self.rx_buf.len() >= self.rx_want {
                self.rx_open = false;
                let payload = core::mem::take(&mut self.rx_buf);
                let cmd = self.rx_cmd;
                self.dispatch(cid, cmd, &payload);
            }
        }
    }

    /// Take the token's next queued report, or model the wait
    /// for one (keepalive / touch release / timeout). Public for
    /// the same downstream-harness reason as
    /// [`Self::handle_report`].
    pub fn next_report(&mut self, out: &mut [u8; REPORT_LEN]) -> Result<(), Error> {
        if let Some(r) = self.out_queue.pop_front() {
            *out = r;
            return Ok(());
        }
        if self.pending.is_some() {
            let release = self.touched
                || self
                    .auto_touch_after
                    .map(|n| self.keepalives_sent >= n)
                    .unwrap_or(false);
            if release {
                self.touched = false;
                self.keepalives_sent = 0;
                let pending = self.pending.take().expect("checked");
                self.complete_pending(pending);
                if let Some(r) = self.out_queue.pop_front() {
                    *out = r;
                    return Ok(());
                }
                return Err(Error::Timeout);
            }
            self.keepalives_sent += 1;
            // KEEPALIVE UP_NEEDED on the allocated channel.
            let cid = self.allocated_cid.unwrap_or(0);
            let mut r = [0u8; REPORT_LEN];
            r[0..4].copy_from_slice(&cid.to_be_bytes());
            r[4] = 0x80 | 0x3B;
            r[5..7].copy_from_slice(&1u16.to_be_bytes());
            r[7] = 2; // UP_NEEDED
            *out = r;
            return Ok(());
        }
        Err(Error::Timeout)
    }

    // ── CTAPHID dispatch ────────────────────────────────────────

    fn dispatch(&mut self, cid: u32, cmd: u8, payload: &[u8]) {
        match cmd {
            0x06 => {
                // INIT: nonce is the whole payload (8 bytes).
                if payload.len() != 8 {
                    self.queue_error(cid, 0x03); // INVALID_LEN
                    return;
                }
                let new_cid = if cid == 0xFFFF_FFFF {
                    let c = self.next_cid;
                    self.next_cid = self.next_cid.wrapping_add(1);
                    self.allocated_cid = Some(c);
                    c
                } else {
                    cid
                };
                let mut resp = Vec::with_capacity(17);
                resp.extend_from_slice(payload);
                resp.extend_from_slice(&new_cid.to_be_bytes());
                resp.push(2); // protocol
                resp.push(1); // major
                resp.push(0); // minor
                resp.push(0); // build
                resp.push(0x01 | 0x02); // WINK | CBOR
                self.queue_message(cid, 0x06, &resp);
            }
            0x01 => {
                // PING echoes.
                if Some(cid) == self.allocated_cid {
                    self.queue_message(cid, 0x01, payload);
                } else {
                    self.queue_error(cid, 0x0B); // INVALID_CHANNEL
                }
            }
            0x10 => {
                if Some(cid) != self.allocated_cid {
                    self.queue_error(cid, 0x0B); // INVALID_CHANNEL
                    return;
                }
                if payload.is_empty() {
                    self.queue_status(cid, 0x01);
                    return;
                }
                self.dispatch_ctap(cid, payload[0], &payload[1..]);
            }
            0x11 => {
                // CANCEL: drop parked work.
                self.pending = None;
            }
            _ => {
                if Some(cid) == self.allocated_cid {
                    self.queue_error(cid, 0x01); // INVALID_CMD
                } else {
                    self.queue_error(cid, 0x0B);
                }
            }
        }
    }

    fn dispatch_ctap(&mut self, cid: u32, cmd: u8, params: &[u8]) {
        match cmd {
            0x04 => self.op_get_info(cid),
            0x06 => self.op_client_pin(cid, params),
            0x01 => self.op_make_credential(cid, params),
            0x02 => self.op_get_assertion(cid, params),
            0x08 => self.op_get_next_assertion(cid),
            _ => self.queue_status(cid, 0x01), // INVALID_COMMAND
        }
    }

    fn parse_params(&mut self, cid: u32, params: &[u8]) -> Option<FVal> {
        match fdec(params) {
            Some((v, _)) => Some(v),
            None => {
                self.queue_status(cid, 0x12); // INVALID_CBOR
                None
            }
        }
    }

    // ── getInfo ─────────────────────────────────────────────────

    fn op_get_info(&mut self, cid: u32) {
        let mut options = alloc::vec![
            (FVal::Text("rk".into()), FVal::Bool(true)),
            (FVal::Text("up".into()), FVal::Bool(true)),
            (
                FVal::Text("clientPin".into()),
                FVal::Bool(self.pin.is_some())
            ),
        ];
        options.sort_by(|a, b| a.0.as_text().cmp(&b.0.as_text()));
        let body = FVal::Map(alloc::vec![
            (
                FVal::UInt(1),
                FVal::Array(alloc::vec![
                    FVal::Text("FIDO_2_0".into()),
                    FVal::Text("FIDO_2_1".into())
                ]),
            ),
            (
                FVal::UInt(2),
                FVal::Array(
                    self.advertised_extensions
                        .iter()
                        .map(|e| FVal::Text(e.clone()))
                        .collect(),
                ),
            ),
            (FVal::UInt(3), FVal::Bytes(FIXTURE_AAGUID.to_vec())),
            (FVal::UInt(4), FVal::Map(options)),
            (FVal::UInt(5), FVal::UInt(1200)),
            (FVal::UInt(6), FVal::Array(alloc::vec![FVal::UInt(1)])),
        ]);
        self.queue_cbor_ok(cid, &body);
    }

    // ── clientPIN ───────────────────────────────────────────────

    fn op_client_pin(&mut self, cid: u32, params: &[u8]) {
        let Some(map) = self.parse_params(cid, params) else {
            return;
        };
        let sub = map.get_int(2).and_then(|v| v.as_uint()).unwrap_or(0);
        match sub {
            1 => {
                // getPINRetries
                let body = FVal::Map(alloc::vec![(
                    FVal::UInt(3),
                    FVal::UInt(self.pin_retries as u64)
                )]);
                self.queue_cbor_ok(cid, &body);
            }
            2 => {
                // getKeyAgreement
                let body = FVal::Map(alloc::vec![(
                    FVal::UInt(1),
                    fixture_cose_key(&self.ka_public, -25),
                )]);
                self.queue_cbor_ok(cid, &body);
            }
            3 => {
                // setPIN
                if self.pin.is_some() {
                    self.queue_status(cid, 0x30); // NOT_ALLOWED: PIN already set
                    return;
                }
                let Some(shared) = self.shared_from(&map) else {
                    self.queue_status(cid, 0x14);
                    return;
                };
                let Some(enc) = map.get_int(5).and_then(|v| v.as_bytes()) else {
                    self.queue_status(cid, 0x14);
                    return;
                };
                let Some(plain) = fixture_aes_cbc(&shared, enc, false) else {
                    self.queue_status(cid, 0x02);
                    return;
                };
                match strip_pin_padding(&plain) {
                    Some(pin) if (4..=63).contains(&pin.len()) => {
                        self.pin = Some(pin);
                        self.queue_status(cid, 0x00);
                    }
                    _ => self.queue_status(cid, 0x37), // PIN_POLICY_VIOLATION
                }
            }
            4 => {
                // changePIN
                let Some(shared) = self.shared_from(&map) else {
                    self.queue_status(cid, 0x14);
                    return;
                };
                let (Some(new_enc), Some(param), Some(hash_enc)) = (
                    map.get_int(5).and_then(|v| v.as_bytes()),
                    map.get_int(4).and_then(|v| v.as_bytes()),
                    map.get_int(6).and_then(|v| v.as_bytes()),
                ) else {
                    self.queue_status(cid, 0x14);
                    return;
                };
                // pinUvAuthParam = full HMAC(shared, newPinEnc).
                let expect = lib_hmac_sha256(&shared, new_enc);
                if expect[..] != param[..] {
                    self.queue_status(cid, 0x33); // PIN_AUTH_INVALID
                    return;
                }
                if !self.check_pin_hash_enc(cid, &shared, hash_enc) {
                    return; // status queued by helper (0x31/0x32)
                }
                let Some(plain) = fixture_aes_cbc(&shared, new_enc, false) else {
                    self.queue_status(cid, 0x02);
                    return;
                };
                match strip_pin_padding(&plain) {
                    Some(pin) if (4..=63).contains(&pin.len()) => {
                        self.pin = Some(pin);
                        self.pin_token = None;
                        self.queue_status(cid, 0x00);
                    }
                    _ => self.queue_status(cid, 0x37),
                }
            }
            5 => {
                // getPINToken
                if self.pin.is_none() {
                    self.queue_status(cid, 0x35); // PIN_NOT_SET
                    return;
                }
                if self.pin_retries == 0 {
                    self.queue_status(cid, 0x32); // PIN_BLOCKED
                    return;
                }
                let Some(shared) = self.shared_from(&map) else {
                    self.queue_status(cid, 0x14);
                    return;
                };
                let Some(hash_enc) = map.get_int(6).and_then(|v| v.as_bytes()) else {
                    self.queue_status(cid, 0x14);
                    return;
                };
                let Some(plain) = fixture_aes_cbc(&shared, hash_enc, false) else {
                    self.queue_status(cid, 0x02);
                    return;
                };
                let pin_hash = sha256(self.pin.as_deref().unwrap_or(&[]));
                if plain.len() != 16 || plain[..] != pin_hash[..16] {
                    self.pin_retries -= 1;
                    let status = if self.pin_retries == 0 { 0x32 } else { 0x31 };
                    self.queue_status(cid, status);
                    return;
                }
                self.pin_retries = MAX_PIN_RETRIES;
                let token = self.rng.bytes::<32>();
                self.pin_token = Some(token);
                let Some(enc) = fixture_aes_cbc(&shared, &token, true) else {
                    self.queue_status(cid, 0x02);
                    return;
                };
                let body = FVal::Map(alloc::vec![(FVal::UInt(2), FVal::Bytes(enc))]);
                self.queue_cbor_ok(cid, &body);
            }
            _ => self.queue_status(cid, 0x02), // INVALID_PARAMETER (unknown sub)
        }
    }

    /// Derive the protocol-one shared secret from a clientPIN /
    /// extension keyAgreement member.
    fn shared_from(&self, map: &FVal) -> Option<[u8; 32]> {
        let cose = map.get_int(3)?;
        let xy = fixture_cose_parse(cose)?;
        fixture_ecdh_shared(&self.ka_secret, &xy)
    }

    /// Check pinHashEnc against the current PIN, queueing
    /// 0x31 (or 0x32 when the counter is exhausted) on failure.
    /// True = PIN matched.
    fn check_pin_hash_enc(&mut self, cid: u32, shared: &[u8; 32], hash_enc: &[u8]) -> bool {
        let matched = (|| {
            let plain = fixture_aes_cbc(shared, hash_enc, false)?;
            let pin = self.pin.as_deref()?;
            let pin_hash = sha256(pin);
            Some(plain.len() == 16 && plain[..] == pin_hash[..16])
        })()
        .unwrap_or(false);
        if matched {
            self.pin_retries = MAX_PIN_RETRIES;
            true
        } else {
            if self.pin_retries > 0 {
                self.pin_retries -= 1;
            }
            let status = if self.pin_retries == 0 { 0x32 } else { 0x31 };
            self.queue_status(cid, status);
            false
        }
    }

    /// Verify a makeCredential/getAssertion pinUvAuthParam:
    /// LEFT(HMAC(pinUvAuthToken, clientDataHash), 16).
    fn verify_pin_uv_auth(&self, param: &[u8], client_data_hash: &[u8]) -> bool {
        let Some(token) = self.pin_token else {
            return false;
        };
        let mac = lib_hmac_sha256(&token, client_data_hash);
        param.len() == 16 && param == &mac[..16]
    }

    // ── makeCredential ──────────────────────────────────────────

    fn op_make_credential(&mut self, cid: u32, params: &[u8]) {
        let Some(map) = self.parse_params(cid, params) else {
            return;
        };
        let Some(cdh) = map.get_int(1).and_then(|v| v.as_bytes()) else {
            self.queue_status(cid, 0x14);
            return;
        };
        let cdh: Vec<u8> = cdh.to_vec();
        let Some(rp) = map.get_int(2) else {
            self.queue_status(cid, 0x14);
            return;
        };
        let Some(rp_id) = rp
            .get_text("id")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string())
        else {
            self.queue_status(cid, 0x14);
            return;
        };
        let _rp_name = rp
            .get_text("name")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());
        let Some(user) = map.get_int(3) else {
            self.queue_status(cid, 0x14);
            return;
        };
        let Some(user_id) = user
            .get_text("id")
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())
        else {
            self.queue_status(cid, 0x14);
            return;
        };
        let user_name = user
            .get_text("name")
            .and_then(|v| v.as_text())
            .map(|s| s.to_string());
        // pubKeyCredParams must offer ES256.
        let es256_offered = map
            .get_int(4)
            .and_then(|v| {
                if let FVal::Array(a) = v {
                    Some(a)
                } else {
                    None
                }
            })
            .map(|a| {
                a.iter().any(|e| {
                    e.get_text("alg").and_then(|v| {
                        if let FVal::NInt(n) = v {
                            Some(*n)
                        } else {
                            None
                        }
                    }) == Some(-7)
                })
            })
            .unwrap_or(false);
        if !es256_offered {
            self.queue_status(cid, 0x26); // UNSUPPORTED_ALGORITHM
            return;
        }
        let mut exclude = Vec::new();
        if let Some(FVal::Array(list)) = map.get_int(5) {
            for item in list {
                if let Some(id) = item.get_text("id").and_then(|v| v.as_bytes()) {
                    exclude.push(id.to_vec());
                }
            }
        }
        let want_hmac = map
            .get_int(6)
            .and_then(|e| e.get_text("hmac-secret"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let options = map.get_int(7);
        let resident = options
            .and_then(|o| o.get_text("rk"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let uv_opt = options
            .and_then(|o| o.get_text("uv"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let auth_param = map
            .get_int(8)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec());
        // PIN/UV verification happens before user presence.
        let mut uv_verified = false;
        if uv_opt {
            if self.pin.is_none() {
                self.queue_status(cid, 0x35); // PIN_NOT_SET
                return;
            }
            match &auth_param {
                None => {
                    self.queue_status(cid, 0x36); // PIN_REQUIRED
                    return;
                }
                Some(p) => {
                    if !self.verify_pin_uv_auth(p, &cdh) {
                        self.queue_status(cid, 0x33); // PIN_AUTH_INVALID
                        return;
                    }
                    uv_verified = true;
                }
            }
        } else if let Some(p) = &auth_param {
            if !self.verify_pin_uv_auth(p, &cdh) {
                self.queue_status(cid, 0x33);
                return;
            }
            uv_verified = true;
        }
        self.pending = Some(Pending::MakeCredential(Box::new(MakeWork {
            rp_id,
            user_id,
            user_name,
            exclude,
            want_hmac,
            resident,
            uv_verified,
        })));
    }

    fn complete_make_credential(&mut self, cid: u32, work: MakeWork) {
        // Exclude-list check at completion (after UP, per spec
        // ordering — the token must not leak membership early).
        if work.exclude.iter().any(|id| {
            self.creds
                .iter()
                .any(|c| &c.id == id && c.rp_id == work.rp_id)
        }) {
            self.queue_status(cid, 0x19); // CREDENTIAL_EXCLUDED
            return;
        }
        let cred_id = self.rng.bytes::<32>().to_vec();
        let signing_scalar = self.rng.scalar();
        let mut signing_key = [0u8; 32];
        signing_key.copy_from_slice(&signing_scalar.to_bytes_be());
        let public_xy = scalar_mul_base(&signing_scalar)
            .to_encoded()
            .expect("generator mul");
        let cred_random = self.rng.bytes::<32>();
        let hmac_enabled = work.want_hmac && self.grant_hmac;
        self.creds.push(FixtureCred {
            id: cred_id.clone(),
            rp_id: work.rp_id.clone(),
            user_id: work.user_id.clone(),
            user_name: work.user_name.clone(),
            signing_key,
            cred_random,
            hmac_secret_enabled: hmac_enabled,
            resident: work.resident,
            sign_count: 0,
        });
        // authData: rpIdHash | flags | count(0) | attested.
        let mut auth = Vec::new();
        auth.extend_from_slice(&sha256(work.rp_id.as_bytes()));
        let mut flags = 0x01u8 | 0x40; // UP | AT
        if work.uv_verified {
            flags |= 0x04;
        }
        if hmac_enabled {
            flags |= 0x80; // ED
        }
        auth.push(flags);
        auth.extend_from_slice(&0u32.to_be_bytes());
        auth.extend_from_slice(&FIXTURE_AAGUID);
        auth.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        auth.extend_from_slice(&cred_id);
        auth.extend_from_slice(&fencode(&fixture_cose_key(&public_xy, -7)));
        if hmac_enabled {
            let ext = FVal::Map(alloc::vec![(
                FVal::Text("hmac-secret".into()),
                FVal::Bool(true),
            )]);
            auth.extend_from_slice(&fencode(&ext));
        }
        let body = FVal::Map(alloc::vec![
            (FVal::UInt(1), FVal::Text("none".into())),
            (FVal::UInt(2), FVal::Bytes(auth)),
            (FVal::UInt(3), FVal::Map(alloc::vec![])),
        ]);
        self.queue_cbor_ok(cid, &body);
    }

    // ── getAssertion / getNextAssertion ─────────────────────────

    fn op_get_assertion(&mut self, cid: u32, params: &[u8]) {
        let Some(map) = self.parse_params(cid, params) else {
            return;
        };
        let Some(rp_id) = map
            .get_int(1)
            .and_then(|v| v.as_text())
            .map(|s| s.to_string())
        else {
            self.queue_status(cid, 0x14);
            return;
        };
        let Some(cdh) = map
            .get_int(2)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec())
        else {
            self.queue_status(cid, 0x14);
            return;
        };
        if cdh.len() != 32 {
            self.queue_status(cid, 0x02);
            return;
        }
        let mut cdh32 = [0u8; 32];
        cdh32.copy_from_slice(&cdh);
        let mut allow: Option<Vec<Vec<u8>>> = None;
        if let Some(FVal::Array(list)) = map.get_int(3) {
            let mut ids = Vec::new();
            for item in list {
                if let Some(id) = item.get_text("id").and_then(|v| v.as_bytes()) {
                    ids.push(id.to_vec());
                }
            }
            allow = Some(ids);
        }
        // hmac-secret extension input.
        let mut hmac: Option<(Vec<u8>, [u8; 32])> = None;
        if let Some(ext) = map.get_int(4).and_then(|e| e.get_text("hmac-secret")) {
            let (Some(cose), Some(salt_enc), Some(salt_auth)) = (
                ext.get_int(1),
                ext.get_int(2).and_then(|v| v.as_bytes()),
                ext.get_int(3).and_then(|v| v.as_bytes()),
            ) else {
                self.queue_status(cid, 0x14); // MISSING_PARAMETER
                return;
            };
            let Some(client_xy) = fixture_cose_parse(cose) else {
                self.queue_status(cid, 0x02);
                return;
            };
            let Some(shared) = fixture_ecdh_shared(&self.ka_secret, &client_xy) else {
                self.queue_status(cid, 0x02);
                return;
            };
            let expect = lib_hmac_sha256(&shared, salt_enc);
            if expect[..] != salt_auth[..] {
                self.queue_status(cid, 0x33); // PIN_AUTH_INVALID
                return;
            }
            let Some(salts) = fixture_aes_cbc(&shared, salt_enc, false) else {
                self.queue_status(cid, 0x02);
                return;
            };
            if salts.len() != 32 && salts.len() != 64 {
                self.queue_status(cid, 0x02);
                return;
            }
            hmac = Some((salts, shared));
        }
        let options = map.get_int(5);
        let uv_opt = options
            .and_then(|o| o.get_text("uv"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let auth_param = map
            .get_int(6)
            .and_then(|v| v.as_bytes())
            .map(|b| b.to_vec());
        let mut uv_verified = false;
        if uv_opt {
            if self.pin.is_none() {
                self.queue_status(cid, 0x35);
                return;
            }
            match &auth_param {
                None => {
                    self.queue_status(cid, 0x36);
                    return;
                }
                Some(p) => {
                    if !self.verify_pin_uv_auth(p, &cdh) {
                        self.queue_status(cid, 0x33);
                        return;
                    }
                    uv_verified = true;
                }
            }
        } else if let Some(p) = &auth_param {
            if !self.verify_pin_uv_auth(p, &cdh) {
                self.queue_status(cid, 0x33);
                return;
            }
            uv_verified = true;
        }
        // Match credentials.
        let matches: Vec<usize> = self
            .creds
            .iter()
            .enumerate()
            .filter(|(_, c)| c.rp_id == rp_id)
            .filter(|(_, c)| match &allow {
                None => true,
                Some(ids) => ids.iter().any(|id| id == &c.id),
            })
            .map(|(i, _)| i)
            .collect();
        if matches.is_empty() {
            self.queue_status(cid, 0x2E); // NO_CREDENTIALS
            return;
        }
        if hmac.is_some() && !self.creds[matches[0]].hmac_secret_enabled {
            // hmac-secret requires the credential to have been
            // created with the extension.
            self.queue_status(cid, 0x16); // UNSUPPORTED_EXTENSION
            return;
        }
        let total = matches.len();
        let rest: Vec<(usize, [u8; 32], bool)> = matches[1..]
            .iter()
            .map(|&i| (i, cdh32, uv_verified))
            .collect();
        self.pending = Some(Pending::GetAssertion(Box::new(AssertWork {
            cred_idx: matches[0],
            client_data_hash: cdh32,
            uv_verified,
            hmac,
            total_matches: total,
            rest,
        })));
    }

    fn complete_get_assertion(&mut self, cid: u32, work: AssertWork) {
        self.assertion_rest = work.rest;
        let body = self.build_assertion(
            work.cred_idx,
            &work.client_data_hash,
            work.uv_verified,
            work.hmac.as_ref(),
            Some(work.total_matches),
        );
        match body {
            Ok(body) => self.queue_cbor_ok(cid, &body),
            Err(status) => self.queue_status(cid, status),
        }
    }

    fn op_get_next_assertion(&mut self, cid: u32) {
        if self.assertion_rest.is_empty() {
            self.queue_status(cid, 0x25); // NO_OPERATIONS
            return;
        }
        let (idx, cdh, uv) = self.assertion_rest.remove(0);
        // getNextAssertion carries no new hmac-secret processing.
        match self.build_assertion(idx, &cdh, uv, None, None) {
            Ok(body) => self.queue_cbor_ok(cid, &body),
            Err(status) => self.queue_status(cid, status),
        }
    }

    fn build_assertion(
        &mut self,
        cred_idx: usize,
        client_data_hash: &[u8; 32],
        uv_verified: bool,
        hmac: Option<&(Vec<u8>, [u8; 32])>,
        total: Option<usize>,
    ) -> Result<FVal, u8> {
        let cred = &mut self.creds[cred_idx];
        cred.sign_count = cred.sign_count.wrapping_add(1);
        let sign_count = cred.sign_count;
        let mut flags = 0x01u8; // UP
        if uv_verified {
            flags |= 0x04;
        }
        let mut auth = Vec::new();
        auth.extend_from_slice(&sha256(cred.rp_id.as_bytes()));
        // hmac-secret output (computed before flags: ED depends on it)
        let mut hmac_enc: Option<Vec<u8>> = None;
        if let Some((salts, shared)) = hmac {
            if !cred.hmac_secret_enabled {
                return Err(0x16);
            }
            let mut plain = Vec::new();
            for chunk in salts.chunks_exact(32) {
                plain.extend_from_slice(&lib_hmac_sha256(&cred.cred_random, chunk));
            }
            hmac_enc = fixture_aes_cbc(shared, &plain, true);
            if hmac_enc.is_some() {
                flags |= 0x80; // ED
            }
        }
        auth.push(flags);
        auth.extend_from_slice(&sign_count.to_be_bytes());
        if let Some(enc) = &hmac_enc {
            let ext = FVal::Map(alloc::vec![(
                FVal::Text("hmac-secret".into()),
                FVal::Bytes(enc.clone()),
            )]);
            auth.extend_from_slice(&fencode(&ext));
        }
        let digest = sha256_two(&auth, client_data_hash);
        let (r, s) = sign_p256(&cred.signing_key, &digest).ok_or(0x02u8)?;
        let signature = der_encode_sig(&r, &s);
        let mut entries = alloc::vec![
            (
                FVal::UInt(1),
                FVal::Map(alloc::vec![
                    (FVal::Text("id".into()), FVal::Bytes(cred.id.clone())),
                    (FVal::Text("type".into()), FVal::Text("public-key".into())),
                ]),
            ),
            (FVal::UInt(2), FVal::Bytes(auth)),
            (FVal::UInt(3), FVal::Bytes(signature)),
        ];
        if cred.resident {
            let mut user =
                alloc::vec![(FVal::Text("id".into()), FVal::Bytes(cred.user_id.clone()))];
            if let Some(name) = &cred.user_name {
                user.push((FVal::Text("name".into()), FVal::Text(name.clone())));
            }
            entries.push((FVal::UInt(4), FVal::Map(user)));
        }
        if let Some(total) = total {
            if total > 1 {
                entries.push((FVal::UInt(5), FVal::UInt(total as u64)));
            }
        }
        Ok(FVal::Map(entries))
    }

    fn complete_pending(&mut self, pending: Pending) {
        let cid = self.allocated_cid.unwrap_or(0);
        match pending {
            Pending::MakeCredential(work) => self.complete_make_credential(cid, *work),
            Pending::GetAssertion(work) => self.complete_get_assertion(cid, *work),
        }
    }
}

fn strip_pin_padding(plain: &[u8]) -> Option<Vec<u8>> {
    let mut end = plain.len();
    while end > 0 && plain[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    Some(plain[..end].to_vec())
}

fn der_int(x: &[u8; 32]) -> Vec<u8> {
    let mut v = &x[..];
    while v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
        v = &v[1..];
    }
    let mut out = alloc::vec![0x02];
    if v[0] & 0x80 != 0 {
        out.push((v.len() + 1) as u8);
        out.push(0);
    } else {
        out.push(v.len() as u8);
    }
    out.extend_from_slice(v);
    out
}

fn der_encode_sig(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let ri = der_int(r);
    let si = der_int(s);
    let mut out = alloc::vec![0x30, (ri.len() + si.len()) as u8];
    out.extend_from_slice(&ri);
    out.extend_from_slice(&si);
    out
}

/// Client-side handle to a fixture token: implements the pipe
/// the CTAP2 client talks over.
pub struct FixturePipe {
    token: Rc<RefCell<FixtureToken>>,
}

impl FixturePipe {
    pub fn new(token: Rc<RefCell<FixtureToken>>) -> Self {
        Self { token }
    }
}

impl HidPipe for FixturePipe {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<(), Error> {
        self.token.borrow_mut().handle_report(report);
        Ok(())
    }

    fn read_report(&mut self, out: &mut [u8; REPORT_LEN]) -> Result<(), Error> {
        self.token.borrow_mut().next_report(out)
    }
}
