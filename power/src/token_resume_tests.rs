//! Kernel smokes for the token resume ceremony (`power/token-
//! resume`, issue #1001, lane P5): P3's fixture authenticator
//! driven through the REAL resume path — enrollment through
//! the suspend service's own `enroll`, sealing through
//! `seal_image`, and resume through `resume_with_token` /
//! `attempt_resume` — so the ceremony is exercised at the same
//! seams production uses, against an independent, spec-shaped
//! token the lane does not control.
//!
//! Fixture discipline: the authenticator is P3's
//! `narf_ctap2::fixture_token` — an independent implementation
//! with its own CBOR/crypto path, its own per-credential
//! hmac-secret, and hardware-shaped PIN semantics (8 retries,
//! then blocked, restored only by power cycle). Nothing in
//! these smokes reaches into the token's state to make an
//! assertion pass; the test-side handles only do what a user
//! does (plug a token in, type PINs, read the retry count the
//! token itself reports).
//!
//! The pipe below exists because the custody trait's
//! `Send + Sync` bound cannot be met by P3's `Rc`-based
//! `FixturePipe`: it drives the same token through the token's
//! public report surface behind an IRQ-safe lock instead. The
//! entropy seam, memory store, and recording prompt are
//! compact copies of the resume-env smokes' fixtures
//! (deliberately not shared: the test modules evolve with
//! different lanes).

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;

use narf_ctap2::ctaphid::{HidPipe, REPORT_LEN};
use narf_ctap2::enroll::{
    enroll_token, enrollment_complete, EnrollParams, EnrolledToken, PinSetup,
};
use narf_ctap2::fixture_token::{FixtureRng, FixtureToken};
use narf_ctap2::{Client, Error as CtapError};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use zeroize::Zeroizing;

use crate::suspend_service::{
    attempt_resume, resume_with_token, suspend_client_data_hash, AnchorError, ImageStore,
    KeyCustodyAnchor, KeyEntropy, PolicyLevel, RecordedPolicy, ResumePrompt, ResumeRefusal,
    Secret32, ServiceError, SuspendService, TokenAnchor, TokenAnchorConfig, TokenPinMode,
    TokenUserInterface, UnwrapCtx, WrapCtx, SUSPEND_RP_ID, SUSPEND_USER_NAME,
};

// ── Scripted entropy seam (copy of the P4 fixture) ───────────────────

#[derive(Clone)]
struct ScriptedEntropy {
    present: Rc<Cell<bool>>,
    draws: Rc<Cell<u64>>,
}

impl ScriptedEntropy {
    fn new(present: bool) -> Self {
        Self {
            present: Rc::new(Cell::new(present)),
            draws: Rc::new(Cell::new(0)),
        }
    }
}

impl KeyEntropy for ScriptedEntropy {
    fn has_seed_grade(&self) -> bool {
        self.present.get()
    }

    fn fill_key_material(&self, out: &mut [u8]) -> Result<(), ServiceError> {
        if !self.present.get() {
            out.fill(0);
            return Err(ServiceError::EntropyUnavailable);
        }
        let n = self.draws.get() + 1;
        self.draws.set(n);
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ n.wrapping_mul(0x2545_f491_4f6c_dd1d);
        for byte in out.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (state >> 33) as u8;
        }
        Ok(())
    }
}

// ── Fixture store + prompt (copies of the P4 fixtures) ───────────────

#[derive(Debug)]
struct MemImageStore {
    data: IrqSafeSpinLock<Vec<u8>>,
}

impl MemImageStore {
    fn new(len: usize) -> Self {
        Self {
            data: IrqSafeSpinLock::new(alloc::vec![0u8; len]),
        }
    }

    fn flip_byte(&self, offset: u64) {
        self.data.lock()[offset as usize] ^= 0xff;
    }
}

impl ImageStore for MemImageStore {
    fn len_bytes(&self) -> u64 {
        self.data.lock().len() as u64
    }

    fn read_exact(&self, offset: u64, out: &mut [u8]) -> Result<(), ServiceError> {
        let start = offset as usize;
        let end = start
            .checked_add(out.len())
            .ok_or(ServiceError::Truncated)?;
        let data = self.data.lock();
        if end > data.len() {
            return Err(ServiceError::Truncated);
        }
        out.copy_from_slice(&data[start..end]);
        Ok(())
    }

    fn write_all(&self, offset: u64, data: &[u8]) -> Result<(), ServiceError> {
        let start = offset as usize;
        let end = start.checked_add(data.len()).ok_or(ServiceError::Store)?;
        let mut store = self.data.lock();
        if end > store.len() {
            return Err(ServiceError::Store);
        }
        store[start..end].copy_from_slice(data);
        Ok(())
    }

    fn flush(&self) -> Result<(), ServiceError> {
        Ok(())
    }
}

#[derive(Default)]
struct RecordingPrompt {
    lines: Vec<alloc::string::String>,
}

impl RecordingPrompt {
    fn said_attempt(&self) -> bool {
        self.lines.iter().any(|l| l.contains("attempting resume"))
    }

    fn said_verified(&self) -> bool {
        self.lines.iter().any(|l| l.contains("image verified"))
    }
}

impl ResumePrompt for RecordingPrompt {
    fn say(&mut self, line: &str) {
        self.lines.push(alloc::string::String::from(line));
    }
}

// ── Token fixtures ───────────────────────────────────────────────────

/// A `Send + Sync` pipe over the shared fixture token (see the
/// module docs for why P3's `FixturePipe` cannot serve here).
struct SyncFixturePipe {
    token: Arc<IrqSafeSpinLock<FixtureToken>>,
}

impl SyncFixturePipe {
    fn new(token: Arc<IrqSafeSpinLock<FixtureToken>>) -> Self {
        Self { token }
    }
}

impl HidPipe for SyncFixturePipe {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<(), CtapError> {
        self.token.lock().handle_report(report);
        Ok(())
    }

    fn read_report(&mut self, out: &mut [u8; REPORT_LEN]) -> Result<(), CtapError> {
        self.token.lock().next_report(out)
    }
}

/// The unplugged case: writes vanish, reads time out — no
/// authenticator ever answers, so `Client::connect` fails.
struct NullPipe;

impl HidPipe for NullPipe {
    fn write_report(&mut self, _report: &[u8; REPORT_LEN]) -> Result<(), CtapError> {
        Ok(())
    }

    fn read_report(&mut self, _out: &mut [u8; REPORT_LEN]) -> Result<(), CtapError> {
        Err(CtapError::Timeout)
    }
}

/// The ceremony's scripted user: a queue of PINs to type, and a
/// recording of everything the ceremony said and asked.
#[derive(Clone)]
struct ScriptedUi {
    inner: Arc<IrqSafeSpinLock<UiScript>>,
}

impl Default for ScriptedUi {
    fn default() -> Self {
        Self {
            inner: Arc::new(IrqSafeSpinLock::new(UiScript::default())),
        }
    }
}

#[derive(Default)]
struct UiScript {
    pins: VecDeque<Vec<u8>>,
    lines: Vec<alloc::string::String>,
    pin_asks: Vec<Option<u64>>,
}

impl ScriptedUi {
    fn with_pins(pins: &[&[u8]]) -> Self {
        let ui = Self::default();
        {
            let mut script = ui.inner.lock();
            for pin in pins {
                script.pins.push_back(pin.to_vec());
            }
        }
        ui
    }

    fn pin_asks(&self) -> Vec<Option<u64>> {
        self.inner.lock().pin_asks.clone()
    }

    fn said(&self, needle: &str) -> bool {
        self.inner.lock().lines.iter().any(|l| l.contains(needle))
    }
}

impl TokenUserInterface for ScriptedUi {
    fn say(&mut self, line: &str) {
        self.inner
            .lock()
            .lines
            .push(alloc::string::String::from(line));
    }

    fn read_pin(&mut self, retries_remaining: Option<u64>) -> Option<Zeroizing<Vec<u8>>> {
        let mut script = self.inner.lock();
        script.pin_asks.push(retries_remaining);
        script.pins.pop_front().map(Zeroizing::new)
    }
}

type TestAnchor = TokenAnchor<SyncFixturePipe, FixtureRng, ScriptedUi>;

const PIN: &[u8] = b"123456";
const WRONG_PIN: &[u8] = b"000000";
const STORE_LEN: usize = 3 * 1024 * 1024;
/// First chunk ciphertext of a service-sealed, one-chunk image
/// with an empty hook region: header page (4096) + one manifest
/// page (4096) + hook region (0), per power spec §3.3.
const CHUNK_OFFSET_PLAIN: u64 = 8192;

fn pattern_image(len: usize) -> Vec<u8> {
    let mut img = Vec::with_capacity(len);
    for i in 0..len {
        img.push((i.wrapping_mul(7) % 251) as u8);
    }
    img
}

fn token_policy() -> RecordedPolicy {
    RecordedPolicy {
        level: PolicyLevel::Token,
        policy_epoch: 7,
    }
}

fn make_token(seed: u8) -> Arc<IrqSafeSpinLock<FixtureToken>> {
    let token = Arc::new(IrqSafeSpinLock::new(FixtureToken::new([seed; 32])));
    // The synchronous client cannot touch mid-call; the fixture
    // releases parked operations after two UP_NEEDED keepalives
    // (P3's flow-test knob, modelling a prompt user).
    token.lock().set_auto_touch(2);
    token
}

/// Enroll `token` (credential creation + PIN setup via P3's
/// enrollment surface), then build the service-side anchor
/// around the same session, ready for `SuspendService::enroll`.
fn enroll_on_token(
    token: &Arc<IrqSafeSpinLock<FixtureToken>>,
    pin: Option<&[u8]>,
) -> Result<(TestAnchor, EnrolledToken), CtapError> {
    let pipe = SyncFixturePipe::new(token.clone());
    let mut client = Client::connect(pipe, FixtureRng::new([0xC1; 32]))?;
    let (pin_setup, pin_mode) = match pin {
        Some(pin) => (PinSetup::TouchAndPin(pin), TokenPinMode::TouchAndPin),
        None => (PinSetup::TouchOnly, TokenPinMode::TouchOnly),
    };
    let enrolled = enroll_token(
        &mut client,
        &EnrollParams {
            client_data_hash: suspend_client_data_hash(),
            rp_id: SUSPEND_RP_ID,
            rp_name: Some("NARF Suspend"),
            user_id: &[1, 2, 3],
            user_name: Some(SUSPEND_USER_NAME),
            pin_setup,
        },
    )?;
    // The anchor's wrap runs one assertion immediately
    // (design §4.2 step 2), which needs the PIN once more.
    let ui = match pin {
        Some(pin) => ScriptedUi::with_pins(&[pin]),
        None => ScriptedUi::default(),
    };
    let anchor = TokenAnchor::from_client(
        client,
        ui,
        TokenAnchorConfig {
            pin_mode,
            enroll_credential: Some(enrolled.credential_id.clone()),
            rp_id: SUSPEND_RP_ID,
        },
    );
    Ok((anchor, enrolled))
}

/// A fresh resume-side anchor over `token` (a new session, as
/// the resume environment would open), with `ui` as its user.
fn resume_anchor(
    token: &Arc<IrqSafeSpinLock<FixtureToken>>,
    ui: ScriptedUi,
    pin_mode: TokenPinMode,
) -> Result<TestAnchor, CtapError> {
    TokenAnchor::connect(
        SyncFixturePipe::new(token.clone()),
        FixtureRng::new([0xC2; 32]),
        ui,
        TokenAnchorConfig {
            pin_mode,
            enroll_credential: None,
            rp_id: SUSPEND_RP_ID,
        },
    )
}

struct SealedWorld {
    store: MemImageStore,
    image: Vec<u8>,
    primary: Arc<IrqSafeSpinLock<FixtureToken>>,
    backup: Arc<IrqSafeSpinLock<FixtureToken>>,
}

/// Enroll two DISTINCT tokens (primary + mandatory backup)
/// into one epoch and seal an image under token policy with
/// both slots — the decided enrollment shape (design §4.2).
fn sealed_two_token_image(pin: Option<&[u8]>) -> Result<SealedWorld, CtapError> {
    let mut svc = SuspendService::new(ScriptedEntropy::new(true));
    svc.create_epoch().expect("epoch");
    let primary = make_token(0xA1);
    let backup = make_token(0xB2);
    let (primary_anchor, primary_enrolled) = enroll_on_token(&primary, pin)?;
    let (backup_anchor, backup_enrolled) = enroll_on_token(&backup, pin)?;
    if primary_enrolled.credential_id == backup_enrolled.credential_id {
        return Err(CtapError::Protocol("tokens share a credential id"));
    }
    if !enrollment_complete(&[primary_enrolled, backup_enrolled]) {
        return Err(CtapError::Protocol("enrollment set is not complete"));
    }
    svc.enroll(&primary_anchor).expect("enroll primary");
    svc.enroll(&backup_anchor).expect("enroll backup");
    let image = pattern_image(100_000);
    let mut store = MemImageStore::new(STORE_LEN);
    svc.seal_image(&mut store, token_policy(), &image)
        .expect("seal");
    Ok(SealedWorld {
        store,
        image,
        primary,
        backup,
    })
}

// ── Smokes: the ceremony through the real resume path ────────────────

fn smoke_power_token_resume_primary_touch_pin() -> TestResult {
    let world = match sealed_two_token_image(Some(PIN)) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("enrollment/sealing failed"),
    };
    let ui = ScriptedUi::with_pins(&[PIN]);
    let anchor = match resume_anchor(&world.primary, ui.clone(), TokenPinMode::TouchAndPin) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("resume anchor connect failed"),
    };
    let mut prompt = RecordingPrompt::default();
    let verified = match attempt_resume(&world.store, &[&anchor], &mut prompt) {
        Ok(v) => v,
        Err(r) => {
            return TestResult::Fail(match r {
                ResumeRefusal::FactorUnavailable => "primary resume: factor unavailable",
                ResumeRefusal::FactorRefused => "primary resume: factor refused",
                ResumeRefusal::AuthenticationFailed => "primary resume: authentication failed",
                _ => "primary resume: unexpected refusal",
            })
        }
    };
    if !prompt.said_attempt() || !prompt.said_verified() {
        return TestResult::Fail("prompt discipline broken (attempt/fact lines)");
    }
    if verified.policy().level != PolicyLevel::Token {
        return TestResult::Fail("authenticated policy is not token");
    }
    match verified.read_all(&world.store) {
        Ok(bytes) if bytes == world.image => {}
        _ => return TestResult::Fail("resumed image bytes do not match"),
    }
    if ui.pin_asks() != [None] {
        return TestResult::Fail("ceremony did not ask for the PIN exactly once");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_token_resume_primary_touch_pin);

fn smoke_power_token_resume_backup_token() -> TestResult {
    // Only the BACKUP token is plugged in. The primary slot is
    // tried first (header order), its credential is absent from
    // this token, and the ceremony must still land on the
    // backup slot — any enrolled credential resumes (design
    // §4.9), not just the primary.
    let world = match sealed_two_token_image(Some(PIN)) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("enrollment/sealing failed"),
    };
    let ui = ScriptedUi::with_pins(&[PIN]);
    let mut prompt = RecordingPrompt::default();
    let verified = match resume_with_token(
        &world.store,
        SyncFixturePipe::new(world.backup.clone()),
        FixtureRng::new([0xC2; 32]),
        ui,
        TokenAnchorConfig {
            pin_mode: TokenPinMode::TouchAndPin,
            enroll_credential: None,
            rp_id: SUSPEND_RP_ID,
        },
        &mut prompt,
    ) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("backup token did not resume the image"),
    };
    match verified.read_all(&world.store) {
        Ok(bytes) if bytes == world.image => {}
        _ => return TestResult::Fail("backup-resumed image bytes do not match"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_token_resume_backup_token);

fn smoke_power_token_resume_wrong_pin_counts_then_succeeds() -> TestResult {
    let world = match sealed_two_token_image(Some(PIN)) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("enrollment/sealing failed"),
    };
    let ui = ScriptedUi::with_pins(&[WRONG_PIN, WRONG_PIN, PIN]);
    let anchor = match resume_anchor(&world.primary, ui.clone(), TokenPinMode::TouchAndPin) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("resume anchor connect failed"),
    };
    let mut prompt = RecordingPrompt::default();
    match attempt_resume(&world.store, &[&anchor], &mut prompt) {
        Ok(_) => {}
        Err(_) => return TestResult::Fail("correct PIN after two wrong ones did not resume"),
    }
    // The hints the ceremony passed to the user interface are
    // the TOKEN's counts, read back after each failure: 8
    // retries at mint, one spent per wrong PIN.
    if ui.pin_asks() != [None, Some(7), Some(6)] {
        return TestResult::Fail("ceremony did not surface the token's retry counts");
    }
    if !ui.said("7 attempts remain") || !ui.said("6 attempts remain") {
        return TestResult::Fail("ceremony did not announce the remaining retries");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power",
    smoke_power_token_resume_wrong_pin_counts_then_succeeds
);

fn smoke_power_token_resume_wrong_pin_blocks() -> TestResult {
    let world = match sealed_two_token_image(Some(PIN)) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("enrollment/sealing failed"),
    };
    // Twelve wrong PINs on offer; the token allows eight. The
    // ceremony must stop at the token's limit — not at the
    // script's — refuse, and never verify anything.
    let ui = ScriptedUi::with_pins(&[WRONG_PIN; 12]);
    let anchor = match resume_anchor(&world.primary, ui.clone(), TokenPinMode::TouchAndPin) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("resume anchor connect failed"),
    };
    let mut prompt = RecordingPrompt::default();
    match attempt_resume(&world.store, &[&anchor], &mut prompt) {
        Err(ResumeRefusal::FactorRefused) => {}
        Err(_) => return TestResult::Fail("blocked PIN gave the wrong refusal class"),
        Ok(_) => return TestResult::Fail("blocked PIN resumed the image"),
    }
    if world.primary.lock().pin_retries() != 0 {
        return TestResult::Fail("token retry counter did not reach zero");
    }
    if ui.pin_asks().len() != 8 {
        return TestResult::Fail("ceremony asked for more PINs than the token allows");
    }
    if !ui.said("no attempts remain") {
        return TestResult::Fail("ceremony did not announce the exhausted retries");
    }
    if prompt.said_verified() {
        return TestResult::Fail("blocked PIN still reached a verified fact line");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_token_resume_wrong_pin_blocks);

fn smoke_power_token_resume_pin_abandoned() -> TestResult {
    let world = match sealed_two_token_image(Some(PIN)) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("enrollment/sealing failed"),
    };
    // The user walks away at the PIN prompt: no PIN is ever
    // supplied, so the ceremony refuses — it does not proceed
    // touch-only against a touch+PIN slot, ever.
    let ui = ScriptedUi::default();
    let anchor = match resume_anchor(&world.primary, ui.clone(), TokenPinMode::TouchAndPin) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("resume anchor connect failed"),
    };
    let mut prompt = RecordingPrompt::default();
    match attempt_resume(&world.store, &[&anchor], &mut prompt) {
        Err(ResumeRefusal::FactorRefused) => {}
        Err(_) => return TestResult::Fail("abandoned PIN gave the wrong refusal class"),
        Ok(_) => return TestResult::Fail("abandoned PIN resumed the image"),
    }
    if ui.pin_asks() != [None] {
        return TestResult::Fail("abandoned ceremony asked more than once");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_token_resume_pin_abandoned);

fn smoke_power_token_resume_unplugged_factor_unavailable() -> TestResult {
    let world = match sealed_two_token_image(Some(PIN)) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("enrollment/sealing failed"),
    };
    // No token on the bus at all: the probe finds nothing, and
    // the token-policy image refuses with the absence class —
    // never the OFF path, never a weaker policy (design §10.3).
    let mut prompt = RecordingPrompt::default();
    match resume_with_token(
        &world.store,
        NullPipe,
        FixtureRng::new([0xC2; 32]),
        ScriptedUi::default(),
        TokenAnchorConfig::default(),
        &mut prompt,
    ) {
        Err(ResumeRefusal::FactorUnavailable) => {}
        Err(_) => return TestResult::Fail("unplugged token gave the wrong refusal class"),
        Ok(_) => return TestResult::Fail("unplugged token resumed the image"),
    }
    if !prompt.said_attempt() || prompt.said_verified() {
        return TestResult::Fail("unplugged attempt broke the prompt discipline");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power",
    smoke_power_token_resume_unplugged_factor_unavailable
);

fn smoke_power_token_resume_unenrolled_token_refused() -> TestResult {
    let world = match sealed_two_token_image(Some(PIN)) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("enrollment/sealing failed"),
    };
    // A perfectly good token that was never enrolled: it holds
    // no credential for either slot, so both pairings refuse.
    let stranger = make_token(0xC3);
    let ui = ScriptedUi::with_pins(&[PIN]);
    let anchor = match resume_anchor(&stranger, ui, TokenPinMode::TouchAndPin) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("stranger anchor connect failed"),
    };
    let mut prompt = RecordingPrompt::default();
    match attempt_resume(&world.store, &[&anchor], &mut prompt) {
        Err(ResumeRefusal::FactorRefused) => {}
        Err(_) => return TestResult::Fail("unenrolled token gave the wrong refusal class"),
        Ok(_) => return TestResult::Fail("unenrolled token resumed the image"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_token_resume_unenrolled_token_refused);

fn smoke_power_token_resume_tampered_chunk_refused_after_valid_token() -> TestResult {
    // The token ceremony fully succeeds — the right token, the
    // right PIN, a genuinely unwrapped SMS — and the image
    // STILL refuses, because one chunk byte was flipped after
    // sealing. Token success must never short-circuit
    // verification (design §6.2 steps 4–5): the refusal is the
    // authentication class and no verified fact is announced.
    let world = match sealed_two_token_image(Some(PIN)) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("enrollment/sealing failed"),
    };
    world.store.flip_byte(CHUNK_OFFSET_PLAIN + 100);
    let ui = ScriptedUi::with_pins(&[PIN]);
    let anchor = match resume_anchor(&world.primary, ui.clone(), TokenPinMode::TouchAndPin) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("resume anchor connect failed"),
    };
    let mut prompt = RecordingPrompt::default();
    match attempt_resume(&world.store, &[&anchor], &mut prompt) {
        Err(ResumeRefusal::AuthenticationFailed) => {}
        Err(ResumeRefusal::FactorRefused) => {
            return TestResult::Fail("valid token was refused; tamper not reached")
        }
        Err(_) => return TestResult::Fail("tampered chunk gave the wrong refusal class"),
        Ok(_) => return TestResult::Fail("tampered chunk resumed"),
    }
    if prompt.said_verified() {
        return TestResult::Fail("tampered image reached a verified fact line");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power",
    smoke_power_token_resume_tampered_chunk_refused_after_valid_token
);

fn smoke_power_token_resume_touch_only() -> TestResult {
    // Touch-only enrollment (the explicit non-default choice):
    // the ceremony must never ask for a PIN — the scripted
    // user has none to give, so an ask would abandon and fail
    // the resume — and the image resumes on touch alone.
    let world = match sealed_two_token_image(None) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("touch-only enrollment/sealing failed"),
    };
    let ui = ScriptedUi::default();
    let anchor = match resume_anchor(&world.primary, ui.clone(), TokenPinMode::TouchOnly) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("resume anchor connect failed"),
    };
    let mut prompt = RecordingPrompt::default();
    let verified = match attempt_resume(&world.store, &[&anchor], &mut prompt) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("touch-only resume refused"),
    };
    match verified.read_all(&world.store) {
        Ok(bytes) if bytes == world.image => {}
        _ => return TestResult::Fail("touch-only image bytes do not match"),
    }
    if !ui.pin_asks().is_empty() {
        return TestResult::Fail("touch-only ceremony asked for a PIN");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_token_resume_touch_only);

// ── Smoke: the anchor alone (framing, epoch binding, tamper) ─────────

fn smoke_power_token_anchor_wrap_unwrap_round_trip() -> TestResult {
    let token = make_token(0xD4);
    let (anchor, _enrolled) = match enroll_on_token(&token, Some(PIN)) {
        Ok(pair) => pair,
        Err(_) => return TestResult::Fail("enrollment failed"),
    };
    let secret = Secret32::mint([0x77; 32]);
    let wrapped = match anchor.wrap(&WrapCtx { sms_epoch: 3 }, &secret) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("anchor wrap failed"),
    };
    // A fresh session (as at resume) unwraps under the same
    // epoch; the credential comes from the slot params, not
    // from the anchor's construction.
    let ui = ScriptedUi::with_pins(&[PIN]);
    let resume_side = match resume_anchor(&token, ui, TokenPinMode::TouchAndPin) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("resume anchor connect failed"),
    };
    match resume_side.unwrap(&UnwrapCtx { sms_epoch: 3 }, &wrapped) {
        Ok(s) if s.with_bytes(|b| *b) == [0x77; 32] => {}
        Ok(_) => return TestResult::Fail("unwrapped secret bytes differ"),
        Err(_) => return TestResult::Fail("anchor unwrap failed"),
    }
    // Epoch binding: the same slot under a different epoch
    // context must not open (the epoch is in the KEK info and
    // the AAD).
    let ui = ScriptedUi::with_pins(&[PIN]);
    let resume_side = match resume_anchor(&token, ui, TokenPinMode::TouchAndPin) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("resume anchor reconnect failed"),
    };
    match resume_side.unwrap(&UnwrapCtx { sms_epoch: 4 }, &wrapped) {
        Err(AnchorError::Failed) => {}
        Err(_) => return TestResult::Fail("wrong epoch gave the wrong anchor error"),
        Ok(_) => return TestResult::Fail("slot opened under the wrong epoch"),
    }
    // Tampered blob and garbage params are anchor failures,
    // indistinguishable by construction.
    let mut bad_blob = wrapped.clone();
    let last = bad_blob.blob.len() - 1;
    bad_blob.blob[last] ^= 0xff;
    let ui = ScriptedUi::with_pins(&[PIN]);
    let resume_side = match resume_anchor(&token, ui, TokenPinMode::TouchAndPin) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("resume anchor reconnect failed"),
    };
    match resume_side.unwrap(&UnwrapCtx { sms_epoch: 3 }, &bad_blob) {
        Err(AnchorError::Failed) => {}
        Err(_) => return TestResult::Fail("tampered blob gave the wrong anchor error"),
        Ok(_) => return TestResult::Fail("tampered blob opened"),
    }
    let mut bad_params = wrapped.clone();
    bad_params.params = alloc::vec![0xff, 0x01, 0x02];
    match resume_side.unwrap(&UnwrapCtx { sms_epoch: 3 }, &bad_params) {
        Err(AnchorError::Failed) => {}
        Err(_) => return TestResult::Fail("garbage params gave the wrong anchor error"),
        Ok(_) => return TestResult::Fail("garbage params opened"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_power_token_anchor_wrap_unwrap_round_trip);
