//! Kernel smokes for the suspend policy engine
//! (`power/suspend-service/policy`, issue #1006).
//!
//! The fixtures pin the *decided* policy surface (decision sheet,
//! 2026-10-26) the way the fleet pins every guarantee: each rule
//! gets a fixture that would fail if the rule were violated.
//!
//! - Decision 4 (fresh-install default): two tokens install at
//!   TOKEN, one token installs at PASSPHRASE, no factors install
//!   nothing — and no path installs OFF.
//! - Decision 1 (PIN default): a fresh TOKEN config records
//!   touch+PIN, and a PIN-gated token refuses until its PIN is
//!   presented.
//! - Decision 2 (recovery slot): the passphrase recovery slot is
//!   enrolled by default on the first epoch, is refused when
//!   opted out, and opens a composition image when the primary
//!   composition fails — because it was enrolled and recorded,
//!   not because anything fell back.
//! - Decision 3 (floor / OFF): the floor refuses downgrades, OFF
//!   needs the explicit confirmation token, and the *recorded*
//!   policy governs resume — an image written under TOKEN opens
//!   by token after the machine's config has moved on, and an
//!   image whose slot set does not realize its recorded level
//!   refuses before any anchor is invoked (the downgrade shape).
//! - Decision 5 (S3 posture): RAM suspend is permitted at every
//!   level, with the exposure note present.
//! - Composition (§8.5): token+TPM opens only with one share from
//!   each factor group; either share alone — through the policy
//!   path or P1's raw single-anchor path — yields nothing.
//!
//! Fixture anchors are the trait-seam species of P1's test anchor
//! (published construction, params = counter ‖ id, unwrap copies
//! only the counter prefix), generalized over kind with honest
//! gates: a token's presence/PIN, a TPM's PCR-policy state. Their
//! secrets are published labels — custody theatre, exactly like
//! the anchors they stand in for are not.

extern crate alloc;

use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::suspend_service::{
    default_token_verification, factor_plan, floor_satisfied, fresh_install_default, level_rank,
    open_with_policy, ram_suspend_permitted, validate_slot_set, AnchorError, AnchorKind,
    FactorPlan, FactorSet, FreshInstall, ImageStore, KeyCustodyAnchor, KeyEntropy, OffConfirmation,
    PolicyChange, PolicyConfig, PolicyError, PolicyLevel, PolicyStore, RecordedPolicy, Secret32,
    ServiceError, SlotRecord, SuspendService, TokenVerification, UnwrapCtx, WrapCtx, WrappedSlot,
    S3_RAM_EXPOSURE_NOTE,
};

// ── Scripted entropy seam (P1 species) ───────────────────────────────

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

// ── Fixture store (P1 species) ───────────────────────────────────────

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

// ── Fixture anchors ──────────────────────────────────────────────────

fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hkdf_extract(None, ikm);
    let okm = hkdf_expand(&prk, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

/// One fixture anchor species for every factor kind: the gates
/// differ per kind (a token's presence and PIN, a TPM's PCR
/// policy), the wrap construction is P1's published one.
#[derive(Debug)]
struct FixtureAnchor {
    kind: AnchorKind,
    id: &'static str,
    secret: [u8; 32],
    present: AtomicBool,
    policy_ok: AtomicBool,
    requires_pin: bool,
    pin_ok: AtomicBool,
    wraps: AtomicU64,
    unwraps: AtomicU64,
}

impl FixtureAnchor {
    fn new(kind: AnchorKind, id: &'static str, present: bool, requires_pin: bool) -> Self {
        let mut ikm = Vec::new();
        ikm.extend_from_slice(b"narf-suspend/policy-fixture-anchor");
        ikm.extend_from_slice(id.as_bytes());
        Self {
            kind,
            id,
            secret: hkdf32(&ikm, b"secret"),
            present: AtomicBool::new(present),
            policy_ok: AtomicBool::new(true),
            requires_pin,
            pin_ok: AtomicBool::new(false),
            wraps: AtomicU64::new(0),
            unwraps: AtomicU64::new(0),
        }
    }

    fn token(id: &'static str) -> Self {
        Self::new(AnchorKind::Token, id, false, false)
    }

    fn token_with_pin(id: &'static str) -> Self {
        Self::new(AnchorKind::Token, id, false, true)
    }

    fn tpm(id: &'static str) -> Self {
        Self::new(AnchorKind::Tpm, id, true, false)
    }

    fn passphrase(id: &'static str) -> Self {
        Self::new(AnchorKind::Passphrase, id, true, false)
    }

    fn grant_presence(&self) {
        self.present.store(true, Ordering::SeqCst);
    }

    fn present_pin(&self) {
        self.pin_ok.store(true, Ordering::SeqCst);
    }

    /// Model a firmware update: the PCR state the TPM anchor
    /// sealed under no longer matches (design §8.3's expected,
    /// documented refusal).
    fn drift_pcrs(&self) {
        self.policy_ok.store(false, Ordering::SeqCst);
    }

    fn unwrap_calls(&self) -> u64 {
        self.unwraps.load(Ordering::SeqCst)
    }

    fn kek(&self, epoch: u64, counter: u64) -> [u8; 32] {
        let mut info = Vec::with_capacity(32);
        info.extend_from_slice(b"narf-suspend/policy-fixture-kek");
        info.extend_from_slice(&epoch.to_le_bytes());
        info.extend_from_slice(&counter.to_le_bytes());
        hkdf32(&self.secret, &info)
    }
}

impl KeyCustodyAnchor for FixtureAnchor {
    fn kind(&self) -> AnchorKind {
        self.kind
    }

    fn wrap(&self, ctx: &WrapCtx, secret: &Secret32) -> Result<WrappedSlot, AnchorError> {
        let counter = self.wraps.fetch_add(1, Ordering::SeqCst);
        let kek = self.kek(ctx.sms_epoch, counter);
        let mut nonce_info = Vec::with_capacity(16);
        nonce_info.extend_from_slice(b"nonce");
        nonce_info.extend_from_slice(&counter.to_le_bytes());
        let nonce_full = hkdf32(&kek, &nonce_info);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);
        let mut aad = Vec::with_capacity(8 + self.id.len());
        aad.extend_from_slice(&ctx.sms_epoch.to_le_bytes());
        aad.extend_from_slice(self.id.as_bytes());
        let mut ct = [0u8; 32];
        secret.with_bytes(|s| ct.copy_from_slice(s));
        let tag = chacha20_poly1305_seal(&kek, &nonce, &aad, &mut ct);
        let mut blob = Vec::with_capacity(12 + 32 + 16);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        blob.extend_from_slice(&tag);
        let mut params = counter.to_le_bytes().to_vec();
        params.extend_from_slice(self.id.as_bytes());
        Ok(WrappedSlot { params, blob })
    }

    fn unwrap(&self, ctx: &UnwrapCtx, slot: &WrappedSlot) -> Result<Secret32, AnchorError> {
        self.unwraps.fetch_add(1, Ordering::SeqCst);
        if self.requires_pin && !self.pin_ok.load(Ordering::SeqCst) {
            return Err(AnchorError::Refused);
        }
        if !self.present.load(Ordering::SeqCst) {
            return Err(AnchorError::Refused);
        }
        if self.kind == AnchorKind::Tpm && !self.policy_ok.load(Ordering::SeqCst) {
            return Err(AnchorError::Refused);
        }
        if slot.params.len() != 8 + self.id.len() || slot.blob.len() != 12 + 32 + 16 {
            return Err(AnchorError::Failed);
        }
        let mut counter_b = [0u8; 8];
        counter_b.copy_from_slice(&slot.params[..8]);
        let kek = self.kek(ctx.sms_epoch, u64::from_le_bytes(counter_b));
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&slot.blob[..12]);
        let mut ct = [0u8; 32];
        ct.copy_from_slice(&slot.blob[12..44]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&slot.blob[44..]);
        let mut aad = Vec::with_capacity(8 + self.id.len());
        aad.extend_from_slice(&ctx.sms_epoch.to_le_bytes());
        aad.extend_from_slice(self.id.as_bytes());
        if !chacha20_poly1305_open(&kek, &nonce, &aad, &mut ct, &tag) {
            return Err(AnchorError::Failed);
        }
        Ok(Secret32::mint(ct))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

const STORE_LEN: usize = 3 * 1024 * 1024;

fn pattern_image(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x: u32 = 0x1234_5678;
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn new_service() -> SuspendService<ScriptedEntropy> {
    SuspendService::new(ScriptedEntropy::new(true))
}

/// Open via the policy path, verify the whole image, and check the
/// plaintext round-trips byte for byte.
fn assert_image_opens(
    store: &MemImageStore,
    anchors: &[&dyn KeyCustodyAnchor],
    image: &[u8],
) -> Result<(), &'static str> {
    let opened = match open_with_policy(store, anchors) {
        Ok(o) => o,
        Err(_) => return Err("open_with_policy failed"),
    };
    if opened.image_len() != image.len() as u64 {
        return Err("authenticated image length mismatch");
    }
    let trusted = match opened.verify_all(store) {
        Ok(t) => t,
        Err(_) => return Err("verify_all failed"),
    };
    let mut out = Vec::new();
    for index in 0..trusted.chunk_count() {
        if trusted.read_chunk(store, index, &mut out).is_err() {
            return Err("read_chunk failed");
        }
    }
    if out != image {
        return Err("reassembled image differs from the sealed plaintext");
    }
    Ok(())
}

fn slot_kinds(svc: &SuspendService<ScriptedEntropy>, epoch: u64) -> Vec<AnchorKind> {
    let area = svc.slot_area();
    let mut kinds: Vec<AnchorKind> = area
        .records_for(epoch)
        .map(|rs| rs.iter().map(|r| r.kind).collect())
        .unwrap_or_default();
    kinds.sort_by_key(|k| k.code());
    kinds
}

/// A machine provisioned at TOKEN with two tokens and (unless
/// opted out) a passphrase recovery slot, floor OFF.
fn token_machine(
    recovery_opt_out: bool,
) -> (
    PolicyStore,
    SuspendService<ScriptedEntropy>,
    FixtureAnchor,
    FixtureAnchor,
    FixtureAnchor,
) {
    let t1 = FixtureAnchor::token("primary");
    let t2 = FixtureAnchor::token("backup");
    let pp = FixtureAnchor::passphrase("recovery");
    let mut store = PolicyStore::new();
    let mut svc = new_service();
    let installed = store.provision_fresh_install(
        &mut svc,
        FreshInstall {
            factors: FactorSet {
                tokens: vec![&t1, &t2],
                tpms: vec![],
                passphrases: vec![&pp],
            },
            floor: PolicyLevel::Off,
            recovery_opt_out,
            token_verification: None,
        },
    );
    assert!(installed.is_ok(), "token machine provisioning failed");
    (store, svc, t1, t2, pp)
}

/// A machine provisioned at TOKEN and then changed to TOKEN+TPM
/// with the recovery slot carried along.
fn composition_machine() -> (
    PolicyStore,
    SuspendService<ScriptedEntropy>,
    FixtureAnchor,
    FixtureAnchor,
    FixtureAnchor,
    FixtureAnchor,
) {
    let (mut store, mut svc, t1, t2, pp) = token_machine(false);
    let tpm = FixtureAnchor::tpm("machine");
    let changed = store.change_level(
        &mut svc,
        PolicyChange {
            level: PolicyLevel::TokenTpm,
            factors: FactorSet {
                tokens: vec![&t1, &t2],
                tpms: vec![&tpm],
                passphrases: vec![&pp],
            },
            off_confirmation: None,
            include_recovery: None,
            token_verification: None,
        },
    );
    assert!(changed.is_ok(), "composition change failed");
    (store, svc, t1, t2, tpm, pp)
}

// ── Decision 4 + 1 + 2: fresh install ────────────────────────────────

fn smoke_policy_fresh_install_two_tokens() -> TestResult {
    let (store, mut svc, t1, _t2, pp) = token_machine(false);
    let config = match store.config() {
        Some(c) => *c,
        None => return TestResult::Fail("no config recorded"),
    };
    // Decision 4: ≥2 tokens → TOKEN. Decision 1: the recorded
    // default for a token-only machine is touch+PIN.
    if config.level != PolicyLevel::Token || config.policy_epoch != 1 {
        return TestResult::Fail("fresh install did not land on TOKEN epoch 1");
    }
    if config.token_verification != TokenVerification::TouchAndPin {
        return TestResult::Fail("token-only default is not touch+PIN");
    }
    // Decision 2: the recovery slot is there by default.
    let kinds = slot_kinds(&svc, 1);
    if kinds != [AnchorKind::Token, AnchorKind::Token, AnchorKind::Passphrase] {
        return TestResult::Fail("slot set is not two tokens + recovery passphrase");
    }
    // And the machine works: seal, open by token, open by recovery.
    let image = pattern_image(1_500_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal under fresh TOKEN policy failed");
    }
    t1.grant_presence();
    if let Err(e) = assert_image_opens(&backing, &[&t1], &image) {
        return TestResult::Fail(e);
    }
    if let Err(e) = assert_image_opens(&backing, &[&pp], &image) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_fresh_install_two_tokens
);

fn smoke_policy_fresh_install_one_token_passphrase() -> TestResult {
    // Decision 4, other branch: a single token cannot satisfy the
    // backup mandate, so the default is PASSPHRASE and the token
    // is not enrolled at all.
    let t1 = FixtureAnchor::token("only");
    let pp = FixtureAnchor::passphrase("user");
    let mut store = PolicyStore::new();
    let mut svc = new_service();
    let recorded = match store.provision_fresh_install(
        &mut svc,
        FreshInstall {
            factors: FactorSet {
                tokens: vec![&t1],
                tpms: vec![],
                passphrases: vec![&pp],
            },
            floor: PolicyLevel::Off,
            recovery_opt_out: false,
            token_verification: None,
        },
    ) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("one-token install failed"),
    };
    if recorded.level != PolicyLevel::Passphrase {
        return TestResult::Fail("one-token install did not default to PASSPHRASE");
    }
    if slot_kinds(&svc, 1) != [AnchorKind::Passphrase] {
        return TestResult::Fail("one-token install enrolled something besides the passphrase");
    }
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal under PASSPHRASE failed");
    }
    if let Err(e) = assert_image_opens(&backing, &[&pp], &image) {
        return TestResult::Fail(e);
    }
    // The unenrolled token is not a path in, even touched.
    t1.grant_presence();
    if open_with_policy(&backing, &[&t1]).is_ok() {
        return TestResult::Fail("unenrolled token opened a PASSPHRASE image");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_fresh_install_one_token_passphrase
);

fn smoke_policy_fresh_install_unsatisfiable() -> TestResult {
    // No factors at all: the computed default (PASSPHRASE) has
    // nothing to enroll — refuse, leave nothing behind.
    let mut store = PolicyStore::new();
    let mut svc = new_service();
    let result = store.provision_fresh_install(
        &mut svc,
        FreshInstall {
            factors: FactorSet {
                tokens: vec![],
                tpms: vec![],
                passphrases: vec![],
            },
            floor: PolicyLevel::Off,
            recovery_opt_out: false,
            token_verification: None,
        },
    );
    if result != Err(PolicyError::Unsatisfiable) {
        return TestResult::Fail("factor-less install was not refused as unsatisfiable");
    }
    // One token and no passphrase: same refusal (the token alone
    // realizes no level).
    let t1 = FixtureAnchor::token("only");
    let result = store.provision_fresh_install(
        &mut svc,
        FreshInstall {
            factors: FactorSet {
                tokens: vec![&t1],
                tpms: vec![],
                passphrases: vec![],
            },
            floor: PolicyLevel::Off,
            recovery_opt_out: false,
            token_verification: None,
        },
    );
    if result != Err(PolicyError::Unsatisfiable) {
        return TestResult::Fail("token-only install was not refused as unsatisfiable");
    }
    if store.config().is_some() {
        return TestResult::Fail("a refused install recorded a policy");
    }
    // The default function itself: OFF is unreachable from it.
    if fresh_install_default(0) != PolicyLevel::Passphrase
        || fresh_install_default(1) != PolicyLevel::Passphrase
        || fresh_install_default(2) != PolicyLevel::Token
        || fresh_install_default(9) != PolicyLevel::Token
    {
        return TestResult::Fail("fresh-install default mapping is wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_fresh_install_unsatisfiable
);

fn smoke_policy_recovery_opt_out() -> TestResult {
    // Decision 2's other side: opting out is honoured exactly —
    // no recovery slot, and the passphrase is not a path in.
    let (store, mut svc, t1, _t2, pp) = token_machine(true);
    if slot_kinds(&svc, 1) != [AnchorKind::Token, AnchorKind::Token] {
        return TestResult::Fail("opted-out install still enrolled a recovery slot");
    }
    match store.config() {
        Some(c) if !c.recovery_slot_default => {}
        _ => return TestResult::Fail("opt-out was not recorded as the standing default"),
    }
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    if open_with_policy(&backing, &[&pp]).is_ok() {
        return TestResult::Fail("passphrase opened an image with no recovery slot");
    }
    t1.grant_presence();
    if let Err(e) = assert_image_opens(&backing, &[&t1], &image) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_recovery_opt_out
);

// ── Decision 3: floor, OFF, recorded policy ──────────────────────────

fn smoke_policy_floor_enforced() -> TestResult {
    let t1 = FixtureAnchor::token("primary");
    let t2 = FixtureAnchor::token("backup");
    let pp = FixtureAnchor::passphrase("recovery");
    let tpm = FixtureAnchor::tpm("machine");
    let mut store = PolicyStore::new();
    let mut svc = new_service();
    // Daniel's profile: floor at TOKEN.
    let installed = store.provision_fresh_install(
        &mut svc,
        FreshInstall {
            factors: FactorSet {
                tokens: vec![&t1, &t2],
                tpms: vec![],
                passphrases: vec![&pp],
            },
            floor: PolicyLevel::Token,
            recovery_opt_out: false,
            token_verification: None,
        },
    );
    if installed.is_err() {
        return TestResult::Fail("install with TOKEN floor failed");
    }
    // PASSPHRASE is below the floor — refused, with the pair named.
    let change = PolicyChange {
        level: PolicyLevel::Passphrase,
        factors: FactorSet {
            tokens: vec![],
            tpms: vec![],
            passphrases: vec![&pp],
        },
        off_confirmation: None,
        include_recovery: None,
        token_verification: None,
    };
    match store.change_level(&mut svc, change) {
        Err(PolicyError::BelowFloor {
            level: PolicyLevel::Passphrase,
            floor: PolicyLevel::Token,
        }) => {}
        _ => return TestResult::Fail("downgrade to PASSPHRASE was not refused by the floor"),
    }
    // OFF is below the floor too — even *with* the confirmation,
    // the floor speaks first.
    let change = PolicyChange {
        level: PolicyLevel::Off,
        factors: FactorSet {
            tokens: vec![],
            tpms: vec![],
            passphrases: vec![],
        },
        off_confirmation: Some(OffConfirmation::explicit()),
        include_recovery: None,
        token_verification: None,
    };
    match store.change_level(&mut svc, change) {
        Err(PolicyError::BelowFloor {
            level: PolicyLevel::Off,
            floor: PolicyLevel::Token,
        }) => {}
        _ => return TestResult::Fail("OFF under a TOKEN floor was not refused by the floor"),
    }
    // Rank algebra the floor stands on.
    if !(floor_satisfied(PolicyLevel::Token, PolicyLevel::Token)
        && floor_satisfied(PolicyLevel::Tpm, PolicyLevel::Token)
        && floor_satisfied(PolicyLevel::TokenTpm, PolicyLevel::Token)
        && !floor_satisfied(PolicyLevel::Passphrase, PolicyLevel::Token)
        && !floor_satisfied(PolicyLevel::Off, PolicyLevel::Passphrase)
        && level_rank(PolicyLevel::TokenTpm) > level_rank(PolicyLevel::Token))
    {
        return TestResult::Fail("level rank algebra is wrong");
    }
    // Upgrades clear the floor: TOKEN+TPM is admitted.
    let change = PolicyChange {
        level: PolicyLevel::TokenTpm,
        factors: FactorSet {
            tokens: vec![&t1, &t2],
            tpms: vec![&tpm],
            passphrases: vec![&pp],
        },
        off_confirmation: None,
        include_recovery: None,
        token_verification: None,
    };
    let recorded = match store.change_level(&mut svc, change) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("upgrade to TOKEN+TPM was refused"),
    };
    if recorded.level != PolicyLevel::TokenTpm || recorded.policy_epoch != 2 {
        return TestResult::Fail("upgrade did not record TOKEN+TPM at policy epoch 2");
    }
    TestResult::Pass
}
kernel_test_in!("power/suspend-service/policy", smoke_policy_floor_enforced);

fn smoke_policy_off_requires_confirmation() -> TestResult {
    let (mut store, mut svc, _t1, _t2, _pp) = token_machine(false);
    // No confirmation token: refused, and nothing moved.
    let change = PolicyChange {
        level: PolicyLevel::Off,
        factors: FactorSet {
            tokens: vec![],
            tpms: vec![],
            passphrases: vec![],
        },
        off_confirmation: None,
        include_recovery: None,
        token_verification: None,
    };
    match store.change_level(&mut svc, change) {
        Err(PolicyError::OffNotConfirmed) => {}
        _ => return TestResult::Fail("OFF without explicit confirmation was not refused"),
    }
    if store.config().map(|c| c.level) != Some(PolicyLevel::Token) {
        return TestResult::Fail("refused OFF change moved the policy");
    }
    // With the explicit act: OFF, recorded honestly.
    let change = PolicyChange {
        level: PolicyLevel::Off,
        factors: FactorSet {
            tokens: vec![],
            tpms: vec![],
            passphrases: vec![],
        },
        off_confirmation: Some(OffConfirmation::explicit()),
        include_recovery: None,
        token_verification: None,
    };
    let recorded = match store.change_level(&mut svc, change) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("confirmed OFF change was refused"),
    };
    if recorded.level != PolicyLevel::Off {
        return TestResult::Fail("confirmed change did not record OFF");
    }
    // An OFF image seals with no epoch rotation and opens with no
    // factors at all — the recorded policy governs, and it says
    // OFF in the authenticated header.
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal under OFF failed");
    }
    let opened = match open_with_policy(&backing, &[]) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("OFF image did not open under its recorded policy"),
    };
    if opened.claims().policy.level != PolicyLevel::Off {
        return TestResult::Fail("OFF image's authenticated record does not say OFF");
    }
    if let Err(e) = assert_image_opens(&backing, &[], &image) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_off_requires_confirmation
);

fn smoke_policy_recorded_policy_governs() -> TestResult {
    // No recovery slot in epoch 1, so the passphrase has no path
    // into the TOKEN image — any opening it gets must come from
    // the recorded policy, not from the machine's later config.
    let (mut store, mut svc, t1, _t2, pp) = token_machine(true);
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal under TOKEN failed");
    }
    // The machine's policy moves on to PASSPHRASE (rotation to a
    // new SMS epoch); the image's recorded TOKEN still governs it.
    let change = PolicyChange {
        level: PolicyLevel::Passphrase,
        factors: FactorSet {
            tokens: vec![],
            tpms: vec![],
            passphrases: vec![&pp],
        },
        off_confirmation: None,
        include_recovery: None,
        token_verification: None,
    };
    if store.change_level(&mut svc, change).is_err() {
        return TestResult::Fail("change to PASSPHRASE failed");
    }
    if svc.current_epoch() != Some(2) {
        return TestResult::Fail("level change did not rotate the SMS epoch");
    }
    t1.grant_presence();
    if let Err(e) = assert_image_opens(&backing, &[&t1], &image) {
        return TestResult::Fail(e);
    }
    if open_with_policy(&backing, &[&pp]).is_ok() {
        return TestResult::Fail("current-config factor opened an image recorded under TOKEN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_recorded_policy_governs
);

fn smoke_policy_pin_default_enforced() -> TestResult {
    // Decision 1 at the seam: the config's touch+PIN default is
    // what enrollment asks of the token; a PIN-gated token that
    // has not seen its PIN refuses, touched or not.
    let t1 = FixtureAnchor::token_with_pin("primary");
    let t2 = FixtureAnchor::token_with_pin("backup");
    let mut store = PolicyStore::new();
    let mut svc = new_service();
    let installed = store.provision_fresh_install(
        &mut svc,
        FreshInstall {
            factors: FactorSet {
                tokens: vec![&t1, &t2],
                tpms: vec![],
                passphrases: vec![],
            },
            floor: PolicyLevel::Off,
            recovery_opt_out: true,
            token_verification: None,
        },
    );
    if installed.is_err() {
        return TestResult::Fail("PIN-token install failed");
    }
    if store.config().map(|c| c.token_verification) != Some(TokenVerification::TouchAndPin) {
        return TestResult::Fail("fresh TOKEN config does not record touch+PIN");
    }
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    t1.grant_presence();
    match open_with_policy(&backing, &[&t1]) {
        Err(ServiceError::Anchor(AnchorError::Refused)) => {}
        _ => return TestResult::Fail("touch without PIN was not refused"),
    }
    t1.present_pin();
    if let Err(e) = assert_image_opens(&backing, &[&t1], &image) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_pin_default_enforced
);

// ── Composition (§8.5) ───────────────────────────────────────────────

fn smoke_policy_composition_round_trip() -> TestResult {
    let (store, mut svc, t1, t2, tpm, _pp) = composition_machine();
    if svc.current_epoch() != Some(2) {
        return TestResult::Fail("composition did not rotate to a fresh epoch");
    }
    // The slot set is the composition: one share per factor
    // (two alternative token shares, one TPM share) + recovery.
    let kinds = slot_kinds(&svc, 2);
    if kinds
        != [
            AnchorKind::Token,
            AnchorKind::Token,
            AnchorKind::Tpm,
            AnchorKind::Passphrase,
        ]
    {
        return TestResult::Fail("composition slot set has the wrong shape");
    }
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal under TOKEN+TPM failed");
    }
    // Either token composes with the TPM share.
    t1.grant_presence();
    if let Err(e) = assert_image_opens(&backing, &[&t1, &tpm], &image) {
        return TestResult::Fail(e);
    }
    t2.grant_presence();
    if let Err(e) = assert_image_opens(&backing, &[&t2, &tpm], &image) {
        return TestResult::Fail(e);
    }
    // The plan the resume side derives says composition, with the
    // recovery alternate present.
    let claims = match crate::suspend_service::parse_claims(&backing) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("parse_claims failed"),
    };
    if factor_plan(&claims.policy, &claims.slots) != (FactorPlan::Composition { recovery: true }) {
        return TestResult::Fail("factor plan is not composition-with-recovery");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_composition_round_trip
);

fn smoke_policy_composition_missing_share_refuses() -> TestResult {
    let (store, mut svc, t1, _t2, tpm, _pp) = composition_machine();
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    t1.grant_presence();
    // Token alone: its share is not the SMS — refuse, do not
    // degrade to a token-only opening. TPM alone: same.
    if open_with_policy(&backing, &[&t1]).is_ok() {
        return TestResult::Fail("token share alone opened a TOKEN+TPM image");
    }
    if open_with_policy(&backing, &[&tpm]).is_ok() {
        return TestResult::Fail("TPM share alone opened a TOKEN+TPM image");
    }
    if open_with_policy(&backing, &[]).is_ok() {
        return TestResult::Fail("no factors opened a TOKEN+TPM image");
    }
    // And through P1's raw single-anchor path a share unwraps to
    // a share — the header seal rejects it as an authentication
    // failure, never as an opening.
    match svc.open_with_anchor(&backing, &t1) {
        Err(ServiceError::AuthenticationFailed) => {}
        _ => return TestResult::Fail("raw anchor path did not fail closed on a share"),
    }
    match svc.open_with_anchor(&backing, &tpm) {
        Err(ServiceError::AuthenticationFailed) => {}
        _ => return TestResult::Fail("raw TPM path did not fail closed on a share"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_composition_missing_share_refuses
);

fn smoke_policy_composition_pcr_drift_and_recovery() -> TestResult {
    let (store, mut svc, t1, _t2, tpm, pp) = composition_machine();
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    // Firmware update: the TPM share's policy no longer matches.
    // The composition refuses — the partner share does not rescue
    // it, and the refusal class is the anchor's own.
    tpm.drift_pcrs();
    t1.grant_presence();
    match open_with_policy(&backing, &[&t1, &tpm]) {
        Err(ServiceError::Anchor(AnchorError::Refused)) => {}
        _ => return TestResult::Fail("drifted PCRs did not refuse the composition"),
    }
    // The enrolled recovery slot — a deliberate, recorded slot,
    // not a fallback invented at resume — still opens the image.
    if let Err(e) = assert_image_opens(&backing, &[&pp], &image) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_composition_pcr_drift_and_recovery
);

fn smoke_policy_downgrade_shape_refused_before_unwrap() -> TestResult {
    // The brief's downgrade shape: an image *recorded* TOKEN+TPM
    // whose slot set carries only a token full-wrap (sealed
    // through the raw service, bypassing the policy layer). Its
    // only satisfiable path would be token-alone — a downgrade —
    // so the policy path must refuse before any anchor runs.
    let t1 = FixtureAnchor::token("primary");
    let tpm = FixtureAnchor::tpm("machine");
    let mut svc = new_service();
    if svc.create_epoch().is_err() || svc.enroll(&t1).is_err() {
        return TestResult::Fail("raw epoch setup failed");
    }
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    let recorded = RecordedPolicy {
        level: PolicyLevel::TokenTpm,
        policy_epoch: 1,
    };
    if svc.seal_image(&mut backing, recorded, &image).is_err() {
        return TestResult::Fail("raw seal failed");
    }
    t1.grant_presence();
    match open_with_policy(&backing, &[&t1, &tpm]) {
        Err(ServiceError::PolicyMismatch) => {}
        _ => return TestResult::Fail("downgrade-shaped image was not refused as PolicyMismatch"),
    }
    if t1.unwrap_calls() != 0 || tpm.unwrap_calls() != 0 {
        return TestResult::Fail("an anchor was invoked for a shape-refused image");
    }
    // Same discipline one level down: recorded TOKEN, one token
    // enrolled — the set does not realize the level.
    let mut backing2 = MemImageStore::new(STORE_LEN);
    let recorded = RecordedPolicy {
        level: PolicyLevel::Token,
        policy_epoch: 1,
    };
    if svc.seal_image(&mut backing2, recorded, &image).is_err() {
        return TestResult::Fail("raw seal (TOKEN) failed");
    }
    match open_with_policy(&backing2, &[&t1]) {
        Err(ServiceError::PolicyMismatch) => {}
        _ => return TestResult::Fail("under-enrolled TOKEN image was not refused"),
    }
    if t1.unwrap_calls() != 0 {
        return TestResult::Fail("an anchor was invoked for the under-enrolled image");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_downgrade_shape_refused_before_unwrap
);

fn smoke_policy_reenroll_after_firmware_update() -> TestResult {
    let (mut store, mut svc, t1, t2, tpm, pp) = composition_machine();
    let image = pattern_image(100_000);
    let mut backing = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing, &image).is_err() {
        return TestResult::Fail("seal failed");
    }
    // Firmware update drifts the PCRs; the sealed TPM share is
    // dead (asserted in the drift smoke). The documented remedy
    // is re-enrollment — same level, fresh SMS epoch, the TPM
    // re-sealed under the new PCR state (a fresh anchor here).
    tpm.drift_pcrs();
    let tpm2 = FixtureAnchor::tpm("machine-updated");
    let epoch_before = svc.current_epoch();
    let recorded = match store.reenroll(
        &mut svc,
        FactorSet {
            tokens: vec![&t1, &t2],
            tpms: vec![&tpm2],
            passphrases: vec![&pp],
        },
    ) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("re-enrollment failed"),
    };
    if recorded.level != PolicyLevel::TokenTpm || recorded.policy_epoch != 2 {
        return TestResult::Fail("re-enrollment moved the level or policy epoch");
    }
    if svc.current_epoch() <= epoch_before {
        return TestResult::Fail("re-enrollment did not rotate the SMS epoch");
    }
    // New images seal and open under the re-enrolled composition.
    let mut backing2 = MemImageStore::new(STORE_LEN);
    if store.seal(&mut svc, &mut backing2, &image).is_err() {
        return TestResult::Fail("seal after re-enrollment failed");
    }
    t1.grant_presence();
    if let Err(e) = assert_image_opens(&backing2, &[&t1, &tpm2], &image) {
        return TestResult::Fail(e);
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_reenroll_after_firmware_update
);

fn smoke_policy_change_to_token_requires_two_tokens() -> TestResult {
    // The backup mandate is an enrollment rule, not a resume-only
    // hope: a level change to a token level with one token in
    // hand refuses before any rotation happens.
    let mut store = PolicyStore::new();
    let mut svc = new_service();
    let pp = FixtureAnchor::passphrase("user");
    let installed = store.provision_fresh_install(
        &mut svc,
        FreshInstall {
            factors: FactorSet {
                tokens: vec![],
                tpms: vec![],
                passphrases: vec![&pp],
            },
            floor: PolicyLevel::Off,
            recovery_opt_out: false,
            token_verification: None,
        },
    );
    if installed.is_err() {
        return TestResult::Fail("passphrase install failed");
    }
    let t1 = FixtureAnchor::token("only");
    let change = PolicyChange {
        level: PolicyLevel::Token,
        factors: FactorSet {
            tokens: vec![&t1],
            tpms: vec![],
            passphrases: vec![],
        },
        off_confirmation: None,
        include_recovery: None,
        token_verification: None,
    };
    match store.change_level(&mut svc, change) {
        Err(PolicyError::Unsatisfiable) => {}
        _ => return TestResult::Fail("one-token change to TOKEN was not refused"),
    }
    if svc.current_epoch() != Some(1) {
        return TestResult::Fail("refused change rotated the epoch anyway");
    }
    let tpm = FixtureAnchor::tpm("machine");
    let change = PolicyChange {
        level: PolicyLevel::TokenTpm,
        factors: FactorSet {
            tokens: vec![&t1],
            tpms: vec![&tpm],
            passphrases: vec![],
        },
        off_confirmation: None,
        include_recovery: None,
        token_verification: None,
    };
    match store.change_level(&mut svc, change) {
        Err(PolicyError::Unsatisfiable) => {}
        _ => return TestResult::Fail("one-token change to TOKEN+TPM was not refused"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_change_to_token_requires_two_tokens
);

// ── Composition rules + decision 5 + the config codec ────────────────

fn rec(kind: AnchorKind, params: &[u8]) -> SlotRecord {
    SlotRecord {
        kind,
        epoch: 1,
        params: params.to_vec(),
        blob: alloc::vec![0u8; 4],
    }
}

fn smoke_policy_validate_slot_set_matrix() -> TestResult {
    let tok_a = rec(AnchorKind::Token, b"a");
    let tok_b = rec(AnchorKind::Token, b"b");
    let tok_a_dup = rec(AnchorKind::Token, b"a");
    let tpm = rec(AnchorKind::Tpm, b"m");
    let pass = rec(AnchorKind::Passphrase, b"p");
    let test = rec(AnchorKind::Test, b"t");
    let cases: Vec<(PolicyLevel, Vec<SlotRecord>, bool)> = alloc::vec![
        // OFF carries nothing.
        (PolicyLevel::Off, alloc::vec![], true),
        (PolicyLevel::Off, alloc::vec![pass.clone()], false),
        // PASSPHRASE: its factor, only its factor.
        (PolicyLevel::Passphrase, alloc::vec![pass.clone()], true),
        (PolicyLevel::Passphrase, alloc::vec![], false),
        (
            PolicyLevel::Passphrase,
            alloc::vec![pass.clone(), tok_a.clone()],
            false,
        ),
        // TOKEN: two distinct tokens; recovery allowed; nothing else.
        (
            PolicyLevel::Token,
            alloc::vec![tok_a.clone(), tok_b.clone()],
            true,
        ),
        (PolicyLevel::Token, alloc::vec![tok_a.clone()], false),
        (
            PolicyLevel::Token,
            alloc::vec![tok_a.clone(), tok_b.clone(), pass.clone()],
            true,
        ),
        (
            PolicyLevel::Token,
            alloc::vec![tok_a.clone(), tok_b.clone(), tpm.clone()],
            false,
        ),
        // A duplicated record is not a second factor.
        (
            PolicyLevel::Token,
            alloc::vec![tok_a.clone(), tok_a_dup],
            false,
        ),
        // TPM: its factor; a token beside it is a shape violation.
        (PolicyLevel::Tpm, alloc::vec![tpm.clone()], true),
        (
            PolicyLevel::Tpm,
            alloc::vec![tpm.clone(), tok_a.clone()],
            false,
        ),
        // TOKEN+TPM: both groups, mandate counts, recovery allowed.
        (
            PolicyLevel::TokenTpm,
            alloc::vec![tok_a.clone(), tok_b.clone(), tpm.clone()],
            true,
        ),
        (
            PolicyLevel::TokenTpm,
            alloc::vec![tok_a.clone(), tok_b.clone()],
            false,
        ),
        (
            PolicyLevel::TokenTpm,
            alloc::vec![tok_a.clone(), tpm.clone()],
            false,
        ),
        (
            PolicyLevel::TokenTpm,
            alloc::vec![tok_a.clone(), tok_b.clone(), tpm.clone(), pass.clone()],
            true,
        ),
        // Test-kind slots realize no level, ever.
        (
            PolicyLevel::Token,
            alloc::vec![test.clone(), tok_b.clone()],
            false,
        ),
    ];
    for (level, slots, expect_ok) in &cases {
        if validate_slot_set(*level, slots).is_ok() != *expect_ok {
            return TestResult::Fail("validate_slot_set matrix case failed");
        }
    }
    // Decision 1's defaults, pinned at the function.
    if default_token_verification(PolicyLevel::Token) != TokenVerification::TouchAndPin
        || default_token_verification(PolicyLevel::TokenTpm) != TokenVerification::TouchOnly
    {
        return TestResult::Fail("token verification defaults are wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_validate_slot_set_matrix
);

fn smoke_policy_s3_posture_and_codec() -> TestResult {
    // Decision 5: permitted at every level, exposure stated.
    for level in [
        PolicyLevel::Off,
        PolicyLevel::Passphrase,
        PolicyLevel::Token,
        PolicyLevel::TokenTpm,
        PolicyLevel::Tpm,
    ] {
        if !ram_suspend_permitted(level) {
            return TestResult::Fail("RAM suspend restricted at some level");
        }
    }
    if !S3_RAM_EXPOSURE_NOTE.contains("RAM") || S3_RAM_EXPOSURE_NOTE.len() < 40 {
        return TestResult::Fail("S3 exposure note is missing or vacuous");
    }
    if !crate::suspend_service::OFF_POLICY_WARNING.contains("No protection") {
        return TestResult::Fail("OFF warning text drifted from design §10.1");
    }
    // The config codec round-trips and refuses tampering.
    let config = PolicyConfig {
        level: PolicyLevel::TokenTpm,
        floor: PolicyLevel::Token,
        policy_epoch: 7,
        token_verification: TokenVerification::TouchAndPin,
        recovery_slot_default: true,
        token_absent: crate::suspend_service::TokenAbsent::Defer,
    };
    let bytes = config.serialize();
    match PolicyConfig::parse(&bytes) {
        Ok(back) if back == config => {}
        _ => return TestResult::Fail("policy config codec did not round-trip"),
    }
    let mut tampered = bytes.clone();
    tampered[0] ^= 0xff;
    if PolicyConfig::parse(&tampered).is_ok() {
        return TestResult::Fail("codec accepted a bad magic");
    }
    let mut extended = bytes.clone();
    extended.push(0);
    if PolicyConfig::parse(&extended).is_ok() {
        return TestResult::Fail("codec accepted trailing garbage");
    }
    let mut bad_level = bytes;
    bad_level[12] = 0xee;
    if PolicyConfig::parse(&bad_level).is_ok() {
        return TestResult::Fail("codec accepted an unknown level code");
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/suspend-service/policy",
    smoke_policy_s3_posture_and_codec
);
