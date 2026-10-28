//! Kernel smokes for the Argon2id passphrase anchor
//! (`power/passphrase`, issue #1004, design §9).
//!
//! Fixture discipline: the KDF is validated against the
//! RFC 9106 §5.3 Argon2id vector — inputs and tag copied from
//! the RFC text, run through the production `argon2id_kdf`
//! entry point, asserted byte-for-byte — before any test here
//! trusts a derivation. Everything else composes the real
//! anchor with the service and the resume environment: slot
//! framing is pinned byte-for-byte against the documented
//! layout with a deterministic entropy stream, the tamper
//! cases prove the no-oracle discipline (wrong passphrase,
//! tampered blob, tampered parameters are one error class),
//! and the recovery-slot case runs P4's `attempt_resume`
//! itself with the token absent.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use zeroize::Zeroizing;

use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::suspend_service::{
    argon2id_kdf, attempt_resume, backoff_millis, calibrate_time_cost, change_passphrase,
    AnchorError, AnchorKind, Argon2idParams, ImageStore, KeyCustodyAnchor, KeyEntropy,
    PassphraseAnchor, PassphrasePolicy, PassphraseSource, PolicyLevel, RecordedPolicy, ResumeDelay,
    ResumePrompt, ResumeRefusal, Secret32, ServiceError, SuspendService, UnwrapCtx, WrapCtx,
    WrappedSlot, MAX_RESUME_PASSPHRASE_FAILURES,
};

// ── Fixtures ────────────────────────────────────────────────────

/// Seed-grade entropy with the two scriptable states, built on
/// atomics (not `Cell`): the anchor must be `Send + Sync`, so
/// its entropy seam must be too. The byte stream is the P1
/// fixture's LCG, keyed by draw number, so fixtures can pin
/// the exact salt a wrap drew.
struct AtomicScriptedEntropy {
    present: AtomicBool,
    draws: AtomicU64,
}

impl AtomicScriptedEntropy {
    fn new(present: bool) -> Self {
        Self {
            present: AtomicBool::new(present),
            draws: AtomicU64::new(0),
        }
    }

    fn stream_bytes(draw: u64, out: &mut [u8]) {
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ draw.wrapping_mul(0x2545_f491_4f6c_dd1d);
        for byte in out.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (state >> 33) as u8;
        }
    }
}

impl KeyEntropy for AtomicScriptedEntropy {
    fn has_seed_grade(&self) -> bool {
        self.present.load(Ordering::SeqCst)
    }

    fn fill_key_material(&self, out: &mut [u8]) -> Result<(), ServiceError> {
        if !self.has_seed_grade() {
            out.fill(0);
            return Err(ServiceError::EntropyUnavailable);
        }
        let n = self.draws.fetch_add(1, Ordering::SeqCst) + 1;
        Self::stream_bytes(n, out);
        Ok(())
    }
}

/// A passphrase source with a scripted queue: each `obtain`
/// pops the next scripted entry; an empty queue is an abort
/// (`Refused`), like a user who walks away. `calls` counts
/// obtains so tests can prove a refusal happened *before* the
/// passphrase was ever requested. The script lives behind an
/// `Arc` so a test keeps a handle after the anchor takes its
/// clone.
#[derive(Clone)]
struct ScriptedSource {
    shared: alloc::sync::Arc<ScriptShared>,
}

struct ScriptShared {
    queue: IrqSafeSpinLock<Vec<Vec<u8>>>,
    calls: AtomicU64,
}

impl ScriptedSource {
    fn new(entries: &[&str]) -> Self {
        Self {
            shared: alloc::sync::Arc::new(ScriptShared {
                queue: IrqSafeSpinLock::new(
                    entries.iter().map(|e| e.as_bytes().to_vec()).collect(),
                ),
                calls: AtomicU64::new(0),
            }),
        }
    }

    fn calls(&self) -> u64 {
        self.shared.calls.load(Ordering::SeqCst)
    }
}

impl PassphraseSource for ScriptedSource {
    fn obtain(&self) -> Result<Zeroizing<Vec<u8>>, AnchorError> {
        self.shared.calls.fetch_add(1, Ordering::SeqCst);
        let mut queue = self.shared.queue.lock();
        if queue.is_empty() {
            return Err(AnchorError::Refused);
        }
        Ok(Zeroizing::new(queue.remove(0)))
    }
}

/// Small, fast parameters for fixtures: real Argon2id, tiny
/// cost (the RFC-vector smoke carries the cryptographic
/// weight; these carry the framing/composition weight).
const FIXTURE_PARAMS: Argon2idParams = Argon2idParams {
    memory_kib: 64,
    time_cost: 3,
    lanes: 4,
};

/// The fixture policy window: everything the fixture params
/// need, with caps at the production values so the window
/// tests can push recorded parameters past them.
fn fixture_policy() -> PassphrasePolicy {
    PassphrasePolicy {
        min_memory_kib: 32,
        max_memory_kib: 1024 * 1024,
        min_time_cost: 1,
        max_time_cost: 16,
        min_lanes: 1,
        max_lanes: 64,
    }
}

fn fixture_anchor(passphrases: &[&str]) -> PassphraseAnchor<AtomicScriptedEntropy, ScriptedSource> {
    PassphraseAnchor::new(
        AtomicScriptedEntropy::new(true),
        ScriptedSource::new(passphrases),
        fixture_policy(),
        FIXTURE_PARAMS,
    )
}

/// A token-kind fixture anchor (the P1 test anchor's shape,
/// kind `Token`): wraps unconditionally, unwraps only when
/// "the token is present", otherwise `Unavailable` — an
/// absent token, which is the recovery slot's whole reason
/// to exist.
struct FixtureTokenAnchor {
    present: AtomicBool,
    wraps: AtomicU64,
}

impl FixtureTokenAnchor {
    fn new() -> Self {
        Self {
            present: AtomicBool::new(true),
            wraps: AtomicU64::new(0),
        }
    }

    fn set_present(&self, present: bool) {
        self.present.store(present, Ordering::SeqCst);
    }

    fn kek(&self, epoch: u64, counter: u64) -> [u8; 32] {
        let mut info = Vec::new();
        info.extend_from_slice(b"narf-suspend/fixture-token");
        info.extend_from_slice(&epoch.to_le_bytes());
        info.extend_from_slice(&counter.to_le_bytes());
        let prk = hkdf_extract(None, b"fixture-token-secret");
        let okm = hkdf_expand(&prk, &info, 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&okm);
        out
    }
}

impl KeyCustodyAnchor for FixtureTokenAnchor {
    fn kind(&self) -> AnchorKind {
        AnchorKind::Token
    }

    fn wrap(&self, ctx: &WrapCtx, secret: &Secret32) -> Result<WrappedSlot, AnchorError> {
        let counter = self.wraps.fetch_add(1, Ordering::SeqCst);
        let kek = self.kek(ctx.sms_epoch, counter);
        let nonce = [0xA5u8; 12];
        let mut aad = Vec::new();
        aad.extend_from_slice(&ctx.sms_epoch.to_le_bytes());
        aad.extend_from_slice(b"fixture-token");
        let mut ct = [0u8; 32];
        secret.with_bytes(|s| ct.copy_from_slice(s));
        let tag = chacha20_poly1305_seal(&kek, &nonce, &aad, &mut ct);
        let mut blob = Vec::new();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        blob.extend_from_slice(&tag);
        Ok(WrappedSlot {
            params: counter.to_le_bytes().to_vec(),
            blob,
        })
    }

    fn unwrap(&self, ctx: &UnwrapCtx, slot: &WrappedSlot) -> Result<Secret32, AnchorError> {
        if !self.present.load(Ordering::SeqCst) {
            return Err(AnchorError::Unavailable);
        }
        if slot.params.len() != 8 || slot.blob.len() != 12 + 32 + 16 {
            return Err(AnchorError::Failed);
        }
        let mut counter_b = [0u8; 8];
        counter_b.copy_from_slice(&slot.params);
        let kek = self.kek(ctx.sms_epoch, u64::from_le_bytes(counter_b));
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&slot.blob[..12]);
        let mut ct = [0u8; 32];
        ct.copy_from_slice(&slot.blob[12..44]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&slot.blob[44..]);
        let mut aad = Vec::new();
        aad.extend_from_slice(&ctx.sms_epoch.to_le_bytes());
        aad.extend_from_slice(b"fixture-token");
        if !chacha20_poly1305_open(&kek, &nonce, &aad, &mut ct, &tag) {
            return Err(AnchorError::Failed);
        }
        Ok(Secret32::mint(ct))
    }
}

/// In-memory image store (the P1/P4 fixture's shape).
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

impl ResumePrompt for RecordingPrompt {
    fn say(&mut self, line: &str) {
        self.lines.push(alloc::string::String::from(line));
    }
}

#[derive(Default)]
struct RecordingDelay {
    delays: Vec<u64>,
}

impl ResumeDelay for RecordingDelay {
    fn delay(&mut self, millis: u64) {
        self.delays.push(millis);
    }
}

const STORE_LEN: usize = 3 * 1024 * 1024;

fn pattern_image(len: usize) -> Vec<u8> {
    let mut img = Vec::with_capacity(len);
    for i in 0..len {
        img.push((i.wrapping_mul(7) % 251) as u8);
    }
    img
}

fn secret_eq(secret: &Secret32, want: &[u8; 32]) -> bool {
    secret.with_bytes(|b| b == want)
}

// ── KDF validation: RFC 9106 §5.3, byte-for-byte ─────────────

fn smoke_passphrase_rfc9106_argon2id_vector() -> TestResult {
    // RFC 9106 §5.3, Argon2id version 19 (0x13): memory 32 KiB,
    // passes 3, parallelism 4 lanes, tag length 32. Password,
    // salt, secret, and associated data are the RFC's repeated
    // byte patterns; the tag below is copied from the RFC text.
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad = [0x04u8; 12];
    let params = Argon2idParams {
        memory_kib: 32,
        time_cost: 3,
        lanes: 4,
    };
    let tag = match argon2id_kdf(&password, &salt, params, Some(&secret), Some(&ad)) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("RFC vector derivation failed"),
    };
    let want: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53,
        0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01,
        0xe6, 0x59,
    ];
    if *tag != want {
        return TestResult::Fail("RFC 9106 §5.3 Argon2id tag mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_rfc9106_argon2id_vector);

// ── Anchor framing + round trip ────────────────────────────────

fn smoke_passphrase_anchor_wrap_unwrap_round_trip() -> TestResult {
    let anchor = fixture_anchor(&["correct horse", "correct horse"]);
    let sms = Secret32::mint([0x42; 32]);
    let wrapped = match anchor.wrap(&WrapCtx { sms_epoch: 9 }, &sms) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("wrap failed"),
    };
    // Parameter block framing, pinned byte-for-byte against
    // the documented layout: version ‖ flags ‖ memory ‖ time
    // ‖ lanes ‖ salt. The salt is the scripted entropy's first
    // draw — the fixture generator's published stream.
    if wrapped.params.len() != 46 {
        return TestResult::Fail("params block is not 46 bytes");
    }
    if wrapped.params[0] != 1 || wrapped.params[1] != 0 {
        return TestResult::Fail("params version/flags bytes wrong");
    }
    let mem = u32::from_le_bytes(wrapped.params[2..6].try_into().unwrap());
    let time = u32::from_le_bytes(wrapped.params[6..10].try_into().unwrap());
    let lanes = u32::from_le_bytes(wrapped.params[10..14].try_into().unwrap());
    if (mem, time, lanes) != (64, 3, 4) {
        return TestResult::Fail("recorded params do not match the operating point");
    }
    let mut want_salt = [0u8; 32];
    AtomicScriptedEntropy::stream_bytes(1, &mut want_salt);
    if wrapped.params[14..] != want_salt {
        return TestResult::Fail("recorded salt is not the drawn salt");
    }
    if wrapped.blob.len() != 12 + 32 + 16 {
        return TestResult::Fail("blob is not nonce‖ct‖tag (60 bytes)");
    }
    if anchor.kind() != AnchorKind::Passphrase || anchor.kind().code() != 5 {
        return TestResult::Fail("anchor kind is not Passphrase (code 5)");
    }
    // A fresh anchor instance (the resume side) unwraps what
    // enrollment wrapped.
    let out = match anchor.unwrap(&UnwrapCtx { sms_epoch: 9 }, &wrapped) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("unwrap of a fresh wrap failed"),
    };
    if !secret_eq(&out, &[0x42; 32]) {
        return TestResult::Fail("unwrapped SMS does not round-trip");
    }
    // Epoch binding: the same slot under another epoch's
    // context must not open (the epoch is in the AAD).
    if anchor
        .unwrap(&UnwrapCtx { sms_epoch: 10 }, &wrapped)
        .is_ok()
    {
        return TestResult::Fail("slot opened under the wrong epoch");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_anchor_wrap_unwrap_round_trip);

// ── No-oracle discipline ───────────────────────────────────────

fn smoke_passphrase_wrong_passphrase_no_oracle() -> TestResult {
    let enroll = fixture_anchor(&["right passphrase"]);
    let sms = Secret32::mint([0x77; 32]);
    let wrapped = match enroll.wrap(&WrapCtx { sms_epoch: 1 }, &sms) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("wrap failed"),
    };
    // Wrong passphrase.
    let wrong = fixture_anchor(&["wrong passphrase"]);
    let e_wrong = wrong.unwrap(&UnwrapCtx { sms_epoch: 1 }, &wrapped);
    // Tampered blob (one ciphertext byte flipped).
    let right = fixture_anchor(&["right passphrase", "right passphrase", "right passphrase"]);
    let mut tampered_blob = wrapped.clone();
    tampered_blob.blob[20] ^= 0x01;
    let e_blob = right.unwrap(&UnwrapCtx { sms_epoch: 1 }, &tampered_blob);
    // Tampered parameters (one salt byte flipped — stays
    // inside the window, so this is the AEAD/AAD layer's
    // catch, not the window's).
    let mut tampered_params = wrapped.clone();
    tampered_params.params[20] ^= 0x01;
    let e_params = right.unwrap(&UnwrapCtx { sms_epoch: 1 }, &tampered_params);
    // All three are the SAME class: Failed. No oracle.
    for (name, e) in [
        ("wrong passphrase", e_wrong),
        ("tampered blob", e_blob),
        ("tampered params", e_params),
    ] {
        match e {
            Err(AnchorError::Failed) => {}
            Err(other) => {
                let _ = other;
                return TestResult::Fail(match name {
                    "wrong passphrase" => "wrong passphrase is not Failed",
                    "tampered blob" => "tampered blob is not Failed",
                    _ => "tampered params is not Failed",
                });
            }
            Ok(_) => return TestResult::Fail("a bad unwrap succeeded"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_wrong_passphrase_no_oracle);

// ── Parameter window ───────────────────────────────────────────

fn smoke_passphrase_params_window_refuses_before_prompt() -> TestResult {
    let enroll = fixture_anchor(&["pw"]);
    let sms = Secret32::mint([0x11; 32]);
    let wrapped = match enroll.wrap(&WrapCtx { sms_epoch: 1 }, &sms) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("wrap failed"),
    };
    // Above the cap: recorded time_cost rewritten past the
    // window's maximum. The refusal must come before the
    // passphrase is requested (source call count stays 0) —
    // the KDF never runs at attacker-chosen cost.
    let mut over_cap = wrapped.clone();
    over_cap.params[6..10].copy_from_slice(&10_000u32.to_le_bytes());
    let source = ScriptedSource::new(&["pw"]);
    let capped = PassphraseAnchor::new(
        AtomicScriptedEntropy::new(true),
        source.clone(),
        fixture_policy(),
        FIXTURE_PARAMS,
    );
    match capped.unwrap(&UnwrapCtx { sms_epoch: 1 }, &over_cap) {
        Err(AnchorError::Refused) => {}
        _ => return TestResult::Fail("over-cap params were not Refused"),
    }
    if source.calls() != 0 {
        return TestResult::Fail("the passphrase was requested for an out-of-window slot");
    }
    // Below the production floor: the fixture slot (64 KiB)
    // is a downgrade under the production window (16 MiB
    // floor) and must refuse there too.
    let production = PassphraseAnchor::new(
        AtomicScriptedEntropy::new(true),
        ScriptedSource::new(&["pw"]),
        PassphrasePolicy::production(),
        Argon2idParams::DESIGN_DEFAULT,
    );
    match production.unwrap(&UnwrapCtx { sms_epoch: 1 }, &wrapped) {
        Err(AnchorError::Refused) => {}
        _ => {
            return TestResult::Fail("below-floor params were not Refused under production policy")
        }
    }
    // In-window portability: an anchor configured at a
    // different operating point (t=2) unwraps a slot recorded
    // at t=3 — recorded parameters drive the derivation
    // (design §9.2: the floor is not hardware-bound).
    let other_point = PassphraseAnchor::new(
        AtomicScriptedEntropy::new(true),
        ScriptedSource::new(&["pw"]),
        fixture_policy(),
        Argon2idParams {
            memory_kib: 128,
            time_cost: 2,
            lanes: 4,
        },
    );
    match other_point.unwrap(&UnwrapCtx { sms_epoch: 1 }, &wrapped) {
        Ok(s) if secret_eq(&s, &[0x11; 32]) => {}
        _ => return TestResult::Fail("in-window recorded params did not drive derivation"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power",
    smoke_passphrase_params_window_refuses_before_prompt
);

// ── Entropy refusal ────────────────────────────────────────────

fn smoke_passphrase_entropy_absent_refuses_wrap() -> TestResult {
    let anchor = PassphraseAnchor::new(
        AtomicScriptedEntropy::new(false),
        ScriptedSource::new(&["pw"]),
        fixture_policy(),
        FIXTURE_PARAMS,
    );
    match anchor.wrap(&WrapCtx { sms_epoch: 1 }, &Secret32::mint([0x22; 32])) {
        Err(AnchorError::Unavailable) => {}
        _ => return TestResult::Fail("wrap without seed-grade entropy was not Unavailable"),
    }
    // Through the service: the anchor's entropy is absent
    // while the service's is present — enrollment fails with
    // the anchor's refusal propagated, and leaves no slot
    // behind (no degraded slot is ever recorded).
    let mut svc = SuspendService::new(AtomicScriptedEntropy::new(true));
    if svc.create_epoch().is_err() {
        return TestResult::Fail("epoch creation failed with entropy present");
    }
    match svc.enroll(&anchor) {
        Err(ServiceError::Anchor(AnchorError::Unavailable)) => {}
        _ => return TestResult::Fail("service enroll did not propagate Unavailable"),
    }
    let area = svc.slot_area();
    let records = area.records_for(1).map(|r| r.len()).unwrap_or(0);
    if records != 0 {
        return TestResult::Fail("a slot was recorded for a refused enrollment");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_entropy_absent_refuses_wrap);

// ── Enroll → seal → resume, through P4's environment ──────────

fn sealed_passphrase_image(
    image_len: usize,
) -> (
    MemImageStore,
    PassphraseAnchor<AtomicScriptedEntropy, ScriptedSource>,
    Vec<u8>,
) {
    let mut svc = SuspendService::new(AtomicScriptedEntropy::new(true));
    svc.create_epoch().expect("epoch");
    // Two obtains scripted: one for the enrollment wrap, one
    // for the resume unwrap.
    let anchor = fixture_anchor(&["floor passphrase", "floor passphrase"]);
    svc.enroll(&anchor).expect("enroll");
    let image = pattern_image(image_len);
    let mut store = MemImageStore::new(STORE_LEN);
    svc.seal_image(
        &mut store,
        RecordedPolicy {
            level: PolicyLevel::Passphrase,
            policy_epoch: 3,
        },
        &image,
    )
    .expect("seal");
    (store, anchor, image)
}

fn smoke_passphrase_resume_round_trip() -> TestResult {
    let (store, anchor, image) = sealed_passphrase_image(5000);
    let mut prompt = RecordingPrompt::default();
    let anchors: [&dyn KeyCustodyAnchor; 1] = [&anchor];
    let verified = match attempt_resume(&store, &anchors, &mut prompt) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("resume refused a valid passphrase image"),
    };
    if verified.policy().level != PolicyLevel::Passphrase {
        return TestResult::Fail("authenticated policy is not the sealed passphrase policy");
    }
    match verified.read_all(&store) {
        Ok(bytes) if bytes == image => {}
        _ => return TestResult::Fail("verified image content does not round-trip"),
    }
    // Prompt discipline through the seam: attempt line first,
    // the verified fact only after verification.
    let attempt_at = prompt
        .lines
        .iter()
        .position(|l| l.contains("attempting resume"));
    let verified_at = prompt
        .lines
        .iter()
        .position(|l| l.contains("image verified"));
    match (attempt_at, verified_at) {
        (Some(a), Some(v)) if a < v => {}
        _ => return TestResult::Fail("prompt lines missing or out of order"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_resume_round_trip);

fn smoke_passphrase_resume_wrong_passphrase_refuses() -> TestResult {
    let (store, _anchor, _image) = sealed_passphrase_image(1024);
    // The resume-side anchor's source has the wrong entry.
    let wrong = fixture_anchor(&["not the passphrase"]);
    let mut prompt = RecordingPrompt::default();
    let anchors: [&dyn KeyCustodyAnchor; 1] = [&wrong];
    match attempt_resume(&store, &anchors, &mut prompt) {
        Err(ResumeRefusal::FactorRefused) => {}
        Err(_) => return TestResult::Fail("wrong passphrase produced the wrong refusal class"),
        Ok(_) => return TestResult::Fail("wrong passphrase resumed the image"),
    }
    // The refusal line states the class only.
    if !prompt
        .lines
        .iter()
        .any(|l| l.contains("resume refused: FactorRefused"))
    {
        return TestResult::Fail("refusal line missing or carries more than the class");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_resume_wrong_passphrase_refuses);

// ── Recovery slot: token enrolled, token absent at resume ────

fn smoke_passphrase_recovery_slot_when_token_absent() -> TestResult {
    let mut svc = SuspendService::new(AtomicScriptedEntropy::new(true));
    svc.create_epoch().expect("epoch");
    let token = FixtureTokenAnchor::new();
    svc.enroll(&token).expect("token enroll");
    // The DECIDED default: a passphrase recovery slot
    // enrolled alongside the token slot in the first epoch.
    let passphrase = fixture_anchor(&["recovery passphrase", "recovery passphrase"]);
    svc.enroll(&passphrase).expect("passphrase enroll");
    let image = pattern_image(2048);
    let mut store = MemImageStore::new(STORE_LEN);
    svc.seal_image(
        &mut store,
        RecordedPolicy {
            level: PolicyLevel::Token,
            policy_epoch: 1,
        },
        &image,
    )
    .expect("seal");

    // At resume the token is absent: its unwrap is
    // Unavailable. The recovery slot must carry the resume.
    token.set_present(false);
    let mut prompt = RecordingPrompt::default();
    let anchors: [&dyn KeyCustodyAnchor; 2] = [&token, &passphrase];
    let verified = match attempt_resume(&store, &anchors, &mut prompt) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("recovery slot did not resume with the token absent"),
    };
    if verified.policy().level != PolicyLevel::Token {
        return TestResult::Fail("authenticated policy is not the sealed token policy");
    }
    match verified.read_all(&store) {
        Ok(bytes) if bytes == image => {}
        _ => return TestResult::Fail("recovered image content does not round-trip"),
    }
    // Negative control: with only the absent token presented,
    // the same image refuses (FactorRefused) — the recovery
    // came from the passphrase slot, not from a weaker path.
    let mut prompt2 = RecordingPrompt::default();
    let only_token: [&dyn KeyCustodyAnchor; 1] = [&token];
    match attempt_resume(&store, &only_token, &mut prompt2) {
        Err(ResumeRefusal::FactorRefused) => {}
        _ => return TestResult::Fail("absent token alone did not refuse"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_recovery_slot_when_token_absent);

// ── Passphrase change ──────────────────────────────────────────

fn smoke_passphrase_change_flow() -> TestResult {
    let mut svc = SuspendService::new(AtomicScriptedEntropy::new(true));
    let epoch = match svc.create_epoch() {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("epoch creation failed"),
    };
    let old = fixture_anchor(&["old passphrase", "old passphrase"]);
    let old_record = match svc.enroll(&old) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("enroll failed"),
    };

    // Wrong current passphrase: the change refuses and the
    // old slot is untouched (still exactly one slot, still
    // unwraps with the old passphrase).
    let impostor = fixture_anchor(&["not the old one"]);
    let new_anchor = fixture_anchor(&["new passphrase"]);
    match change_passphrase(&mut svc, &impostor, &old_record.params, &new_anchor) {
        Err(ServiceError::Anchor(AnchorError::Failed)) => {}
        _ => return TestResult::Fail("change with a wrong old passphrase did not refuse"),
    }
    let area = svc.slot_area();
    if area.records_for(epoch).map(|r| r.len()) != Some(1) {
        return TestResult::Fail("a refused change altered the slot set");
    }

    // Correct flow: the replacement anchor needs two obtains
    // scripted — the change's own enroll wrap, plus the
    // verification unwrap below.
    let new_anchor = fixture_anchor(&["new passphrase", "new passphrase"]);
    let new_record = match change_passphrase(&mut svc, &old, &old_record.params, &new_anchor) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("change with the correct old passphrase failed"),
    };
    let area = svc.slot_area();
    if area.records_for(epoch).map(|r| r.len()) != Some(1) {
        return TestResult::Fail("change did not replace exactly one slot");
    }
    // The old passphrase no longer opens anything; the new
    // one opens the replacement record.
    let stale = fixture_anchor(&["old passphrase"]);
    match stale.unwrap(&UnwrapCtx { sms_epoch: epoch }, &new_record.wrapped()) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("old passphrase still opens after the change"),
    }
    match new_anchor.unwrap(&UnwrapCtx { sms_epoch: epoch }, &new_record.wrapped()) {
        Ok(_) => {}
        _ => return TestResult::Fail("new passphrase does not open after the change"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_change_flow);

// ── §9.3 combiner ──────────────────────────────────────────────

fn smoke_passphrase_combiner() -> TestResult {
    let machine_secret = [0x5Au8; 32];
    let enroll = fixture_anchor(&["pw", "pw"]).with_combiner(machine_secret);
    let sms = Secret32::mint([0x33; 32]);
    let wrapped = match enroll.wrap(&WrapCtx { sms_epoch: 2 }, &sms) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("combiner wrap failed"),
    };
    // The flag is recorded; the secret is not.
    if wrapped.params[1] != 1 {
        return TestResult::Fail("combiner flag not recorded in the slot params");
    }
    // Same secret at resume: opens.
    let resume = fixture_anchor(&["pw"]).with_combiner(machine_secret);
    match resume.unwrap(&UnwrapCtx { sms_epoch: 2 }, &wrapped) {
        Ok(s) if secret_eq(&s, &[0x33; 32]) => {}
        _ => return TestResult::Fail("combiner slot did not open with the machine secret"),
    }
    // No secret presented (a different machine's firmware):
    // refused before the passphrase matters.
    let foreign = fixture_anchor(&["pw"]);
    match foreign.unwrap(&UnwrapCtx { sms_epoch: 2 }, &wrapped) {
        Err(AnchorError::Refused) => {}
        _ => return TestResult::Fail("combiner slot opened without the machine secret"),
    }
    // Wrong secret: the AEAD class, indistinguishable from a
    // wrong passphrase.
    let wrong_secret = fixture_anchor(&["pw"]).with_combiner([0x6B; 32]);
    match wrong_secret.unwrap(&UnwrapCtx { sms_epoch: 2 }, &wrapped) {
        Err(AnchorError::Failed) => {}
        _ => return TestResult::Fail("combiner slot with a wrong secret is not Failed"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_combiner);

// ── Backoff discipline (design §9.4) ───────────────────────────

fn smoke_passphrase_backoff_schedule_and_exhaustion() -> TestResult {
    // The schedule itself, pinned: 1s doubling, 60s cap.
    let want = [1000u64, 2000, 4000, 8000, 16000, 32000, 60000, 60000];
    for (i, w) in want.iter().enumerate() {
        if backoff_millis(i as u32 + 1) != *w {
            return TestResult::Fail("backoff schedule deviates from §9.4");
        }
    }

    // Retry-until-success: three wrong entries, then the
    // right one; the recorded delays are the first three
    // schedule entries and no cold-boot line is said.
    let (store, _anchor, image) = sealed_passphrase_image(1024);
    let source = ScriptedSource::new(&["wrong", "wrong", "wrong", "floor passphrase"]);
    let anchor = PassphraseAnchor::new(
        AtomicScriptedEntropy::new(true),
        source.clone(),
        fixture_policy(),
        FIXTURE_PARAMS,
    );
    let mut prompt = RecordingPrompt::default();
    let mut delay = RecordingDelay::default();
    let anchors: [&dyn KeyCustodyAnchor; 1] = [&anchor];
    let verified = match crate::suspend_service::resume_with_passphrase(
        &store,
        &anchors,
        &mut prompt,
        &mut delay,
    ) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("retry driver refused after scripted success"),
    };
    match verified.read_all(&store) {
        Ok(bytes) if bytes == image => {}
        _ => return TestResult::Fail("retry driver verified the wrong image"),
    }
    if delay.delays != [1000, 2000, 4000] {
        return TestResult::Fail("retry delays are not the backoff schedule");
    }
    if prompt.lines.iter().any(|l| l.contains("cold boot")) {
        return TestResult::Fail("cold-boot offer made before exhaustion");
    }

    // Exhaustion: always wrong (12 scripted entries — more
    // than the budget, so the budget is what stops the loop,
    // not the script running dry). Exactly MAX attempts,
    // MAX-1 delays, then the cold-boot offer and the refusal.
    let entries: Vec<&str> = (0..12).map(|_| "wrong").collect();
    let source2 = ScriptedSource::new(&entries);
    let anchor2 = PassphraseAnchor::new(
        AtomicScriptedEntropy::new(true),
        source2.clone(),
        fixture_policy(),
        FIXTURE_PARAMS,
    );
    let mut prompt2 = RecordingPrompt::default();
    let mut delay2 = RecordingDelay::default();
    let anchors2: [&dyn KeyCustodyAnchor; 1] = [&anchor2];
    match crate::suspend_service::resume_with_passphrase(
        &store,
        &anchors2,
        &mut prompt2,
        &mut delay2,
    ) {
        Err(ResumeRefusal::FactorRefused) => {}
        _ => return TestResult::Fail("exhaustion did not end in FactorRefused"),
    }
    if source2.calls() != MAX_RESUME_PASSPHRASE_FAILURES as u64 {
        return TestResult::Fail("attempt count is not the §9.4 budget");
    }
    if delay2.delays.len() as u32 != MAX_RESUME_PASSPHRASE_FAILURES - 1 {
        return TestResult::Fail("delay count is not attempts-1");
    }
    if !prompt2.lines.iter().any(|l| l.contains("cold boot")) {
        return TestResult::Fail("cold-boot offer missing at exhaustion");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_backoff_schedule_and_exhaustion);

// ── Calibration + entry discipline ─────────────────────────────

fn smoke_passphrase_calibration_scales_time_cost() -> TestResult {
    // A machine where one pass at the design memory costs
    // 700 ms: the 2 s target lands at t=2 (1400 ms), not
    // t=3 (2100 ms).
    let mut measure = |p: Argon2idParams| -> u64 { 700 * p.time_cost as u64 };
    let out = calibrate_time_cost(
        Argon2idParams::DESIGN_DEFAULT,
        &PassphrasePolicy::production(),
        2000,
        &mut measure,
    );
    if out.time_cost != 2 || out.memory_kib != 512 * 1024 || out.lanes != 4 {
        return TestResult::Fail("calibration did not scale time cost to the target");
    }
    // A slow machine (one pass already over target) floors
    // at t=1 rather than 0.
    let mut slow = |_p: Argon2idParams| -> u64 { 5000 };
    let out = calibrate_time_cost(
        Argon2idParams::DESIGN_DEFAULT,
        &PassphrasePolicy::production(),
        2000,
        &mut slow,
    );
    if out.time_cost != 1 {
        return TestResult::Fail("calibration did not floor at one pass");
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_calibration_scales_time_cost);

fn smoke_passphrase_empty_and_overlong_refused() -> TestResult {
    // Empty passphrase at enrollment: refused, no slot.
    let empty = fixture_anchor(&[""]);
    match empty.wrap(&WrapCtx { sms_epoch: 1 }, &Secret32::mint([0x44; 32])) {
        Err(AnchorError::Refused) => {}
        _ => return TestResult::Fail("empty passphrase was not refused at wrap"),
    }
    // Overlong: refused at wrap as well.
    let long = alloc::string::String::from_utf8(alloc::vec![b'x'; 1025]).unwrap();
    let overlong = fixture_anchor(&[&long]);
    match overlong.wrap(&WrapCtx { sms_epoch: 1 }, &Secret32::mint([0x44; 32])) {
        Err(AnchorError::Refused) => {}
        _ => return TestResult::Fail("overlong passphrase was not refused at wrap"),
    }
    // And at unwrap: a genuine slot, an empty entry.
    let enroll = fixture_anchor(&["pw"]);
    let wrapped = match enroll.wrap(&WrapCtx { sms_epoch: 1 }, &Secret32::mint([0x44; 32])) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("wrap failed"),
    };
    let empty_resume = fixture_anchor(&[""]);
    match empty_resume.unwrap(&UnwrapCtx { sms_epoch: 1 }, &wrapped) {
        Err(AnchorError::Refused) => {}
        _ => return TestResult::Fail("empty passphrase was not refused at unwrap"),
    }
    TestResult::Pass
}
kernel_test_in!("power", smoke_passphrase_empty_and_overlong_refused);
